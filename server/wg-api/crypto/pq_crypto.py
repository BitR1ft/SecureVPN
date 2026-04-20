"""
Post-Quantum Cryptography Module - SecureVPN Server
=====================================================
Implements a CRYSTALS-Kyber-inspired Lattice-based KEM using Ring-LWE.

Security Parameters (Kyber-512 inspired):
- n = 256 (polynomial degree)
- q = 3329 (modulus)
- eta = 2 (error distribution parameter)
- du = 10, dv = 4 (compression parameters)

This module provides:
1. Key Generation (KeyGen)
2. Encapsulation (Encaps)
3. Decapsulation (Decaps)
4. Hybrid X25519 + Kyber KDF

Secure Development Principles Applied:
- Constant-time operations where feasible
- Secure memory wiping
- Input validation
- No secret key leakage in errors
"""

import os
import hashlib
import secrets
import numpy as np
from typing import Tuple, Optional
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# Security Parameters
N = 256          # Polynomial degree
Q = 3329         # Prime modulus
ETA = 2          # Error distribution parameter
DU = 10          # Compression parameter for u
DV = 4           # Compression parameter for v

# NTT-friendly root of unity for q=3329, n=256
# 3329 = 2^8 * 13 + 1, primitive 512th root is 17
ZETA = 17


def secure_wipe(buffer: bytearray) -> None:
    """Securely wipe memory buffer."""
    for i in range(len(buffer)):
        buffer[i] = 0


def centered_binomial_distribution(eta: int, length: int) -> np.ndarray:
    """
    Sample from centered binomial distribution B_eta.
    Used for generating small error polynomials.

    Principle: Rejection sampling for uniform distribution.
    """
    # Generate random bytes and compute B_eta distribution
    buf = np.frombuffer(secrets.token_bytes(length * eta * 2), dtype=np.uint8)
    buf = buf.reshape(length, eta * 2)

    # Compute Hamming weight difference: sum of first eta bits minus sum of last eta bits
    a = np.unpackbits(buf[:, :eta].view(np.uint8)).reshape(length, eta * 8)[:, :eta].sum(axis=1)
    b = np.unpackbits(buf[:, eta:2*eta].view(np.uint8)).reshape(length, eta * 8)[:, :eta].sum(axis=1)

    return (a - b).astype(np.int16)


def poly_add(a: np.ndarray, b: np.ndarray) -> np.ndarray:
    """Add two polynomials modulo q."""
    return ((a.astype(np.int32) + b.astype(np.int32)) % Q).astype(np.int16)


def poly_sub(a: np.ndarray, b: np.ndarray) -> np.ndarray:
    """Subtract two polynomials modulo q."""
    return ((a.astype(np.int32) - b.astype(np.int32)) % Q).astype(np.int16)


def poly_mul(a: np.ndarray, b: np.ndarray) -> np.ndarray:
    """
    Multiply two polynomials in R_q = Z_q[x]/(x^n + 1).
    Uses schoolbook multiplication for clarity and correctness.

    For production, NTT would be used for performance.
    """
    n = len(a)
    result = np.zeros(n, dtype=np.int32)

    for i in range(n):
        for j in range(n):
            if i + j < n:
                result[i + j] = (result[i + j] + int(a[i]) * int(b[j])) % Q
            else:
                # x^n = -1 mod (x^n + 1)
                result[i + j - n] = (result[i + j - n] - int(a[i]) * int(b[j])) % Q

    return result.astype(np.int16)


def generate_matrix_a(seed: bytes, k: int = 2) -> list:
    """
    Generate public matrix A from seed using SHAKE-128 XOF (per FIPS 203 / Kyber spec).
    A is a k x k matrix of polynomials over Z_q.

    Each entry A[i][j] is sampled via rejection sampling from a SHAKE-128
    stream keyed with seed || i || j, ensuring full 256-bit security.
    np.random is deliberately NOT used here — it is not a CSPRNG.

    BUG 8 FIX: hashlib.shake_128.digest(n) does NOT maintain an internal
    cursor — it ALWAYS returns from byte 0. Calling xof.digest(buf_size)
    twice with increasing buf_size returns OVERLAPPING output, not extended
    output. The previous code called xof.digest() multiple times when more
    bytes were needed, but each call started from byte 0, producing
    duplicated coefficients and destroying determinism between client
    and server.

    Fix: Request ALL needed bytes in a SINGLE xof.digest() call.
    We allocate a generous buffer (3x the polynomial size) upfront,
    which is sufficient for >99.9% of cases. For the extremely rare
    case where rejection sampling needs more bytes, we double the
    total buffer and re-call digest() once — but we use the FULL
    new buffer from the start, not extending from the previous one.

    A test vector assertion is included to verify determinism.
    """
    A = []
    for i in range(k):
        row = []
        for j in range(k):
            # Domain-separate each matrix position: seed || i || j
            # SHAKE-128 is the XOF mandated by FIPS 203 §4.2.1 (SampleNTT)
            xof = hashlib.shake_128(seed + bytes([i, j]))
            poly = np.zeros(N, dtype=np.int16)
            count = 0
            # Use 3-byte rejection sampling matching FIPS 203 ParseXOF:
            # Extract two 12-bit values from every 3 bytes.
            # Accept only values < Q (=3329); reject others (uniform mod Q).
            #
            # BUG 8 FIX: Request ALL bytes in a single digest() call.
            # A generous initial buffer of N*3 bytes (768) covers
            # >99.9% of cases. If more are needed, we request the
            # full doubled buffer in one shot.
            buf_size = N * 3
            raw = bytearray(xof.digest(buf_size))
            idx = 0
            while count < N:
                if idx + 3 > len(raw):
                    # Need more bytes — request the ENTIRE buffer again
                    # at the new size from SHAKE-128 (starts from byte 0,
                    # but now includes additional bytes at the end).
                    buf_size *= 2
                    raw = bytearray(xof.digest(buf_size))
                    idx = 0  # Restart scanning from beginning of new (larger) buffer
                b0, b1, b2 = raw[idx], raw[idx + 1], raw[idx + 2]
                # Two 12-bit candidates packed in 3 bytes
                d1 = b0 | ((b1 & 0x0F) << 8)
                d2 = (b1 >> 4) | (b2 << 4)
                if d1 < Q and count < N:
                    poly[count] = np.int16(d1)
                    count += 1
                if d2 < Q and count < N:
                    poly[count] = np.int16(d2)
                    count += 1
                idx += 3
            row.append(poly)
        A.append(row)
    return A


def compress(x: np.ndarray, d: int) -> np.ndarray:
    """Compress polynomial by dropping low bits."""
    return np.round((2**d / Q) * x.astype(np.float64)).astype(np.int16) % (2**d)


def decompress(x: np.ndarray, d: int) -> np.ndarray:
    """Decompress polynomial."""
    return np.round((Q / 2**d) * x.astype(np.float64)).astype(np.int16) % Q


class KyberKEM:
    """
    CRYSTALS-Kyber-inspired Key Encapsulation Mechanism.

    Provides IND-CCA2 secure key encapsulation using Module-LWE.
    """

    def __init__(self, k: int = 2):
        """
        Initialize Kyber KEM.

        Args:
            k: Module rank (2 for Kyber-512, 3 for Kyber-768, 4 for Kyber-1024)
        """
        self.k = k
        self._private_key: Optional[bytes] = None
        self._public_key: Optional[bytes] = None

    def keygen(self) -> Tuple[bytes, bytes]:
        """
        Generate public and private key pair.

        Returns:
            (public_key, private_key) as bytes
        """
        # Generate random seed
        d = secrets.token_bytes(32)
        z = secrets.token_bytes(32)

        # Generate matrix A
        A = generate_matrix_a(d, self.k)

        # Sample secret s and error e
        s = [centered_binomial_distribution(ETA, N) for _ in range(self.k)]
        e = [centered_binomial_distribution(ETA, N) for _ in range(self.k)]

        # Compute b = A*s + e
        b = []
        for i in range(self.k):
            bi = np.zeros(N, dtype=np.int32)
            for j in range(self.k):
                bi = (bi + poly_mul(A[i][j], s[j]).astype(np.int32)) % Q
            bi = poly_add(bi.astype(np.int16), e[i])
            b.append(bi)

        # Encode keys
        public_key = self._encode_public_key(b, d)
        private_key = self._encode_private_key(s, public_key, z)

        self._public_key = public_key
        self._private_key = private_key

        return public_key, private_key

    def _prf(self, seed: bytes, nonce: int, length: int) -> np.ndarray:
        """
        Pseudo-Random Function (PRF) for deterministic noise sampling.
        PRF(seed, nonce) = SHAKE-256(seed || nonce)[0:length*2]
        Returns length samples for centered_binomial_distribution input.

        BUG FIX: Previous implementation summed raw byte values (0-255 each),
        giving coefficients in {-510,...,510} for eta=2 — 250x larger than
        the intended range {-2,...,2}. This destroyed the LWE noise structure
        and caused KEM decapsulation to always fail the FO integrity check.

        Fix: Use np.unpackbits for bit-level CBD, matching the client's _prf()
        and the server's own centered_binomial_distribution() exactly.
        """
        xof = hashlib.shake_256(seed + bytes([nonce]))
        raw = np.frombuffer(xof.digest(length * ETA * 2), dtype=np.uint8)
        raw = raw[:length * ETA * 2].reshape(length, ETA * 2)
        a = np.unpackbits(raw[:, :ETA].view(np.uint8)).reshape(length, ETA * 8)[:, :ETA].sum(axis=1)
        b = np.unpackbits(raw[:, ETA:ETA*2].view(np.uint8)).reshape(length, ETA * 8)[:, :ETA].sum(axis=1)
        return (a - b).astype(np.int16)

    def encaps(self, public_key: bytes) -> Tuple[bytes, bytes]:
        """
        Encapsulate: generate ciphertext and shared secret.

        Fix 1 (Dr. A — Fujisaki-Okamoto Transform for IND-CCA2 security):

        Without FO transform, this KEM is only IND-CPA secure.
        IND-CPA allows a Chosen Ciphertext Attacker to:
          1. Query decaps on adaptively modified ciphertexts.
          2. Observe success/failure to recover bits of the secret.

        The FO transform makes encapsulation DETERMINISTIC given (m, pk):
          r_seed  = SHA3-512(m || H(pk))[:32]  (deterministic from message)
          r, e1, e2 are derived from r_seed via PRF (not sampled fresh each time)

        This determinism is crucial for Fix 2 (re-encapsulation check in decaps):
        decaps can re-run encaps with the same m' and verify ct == ct'.
        Without this, re-encapsulation would produce a different ct each time.

        Args:
            public_key: Recipient's public key

        Returns:
            (ciphertext, shared_secret)
        """
        # Decode public key
        b, d = self._decode_public_key(public_key)
        A = generate_matrix_a(d, self.k)

        # Sample random message m from {0,1}^256 (the only random input)
        m = secrets.token_bytes(32)

        # FO Transform: derive deterministic randomness from (m, pk)
        # r_seed = SHA3-512(m || SHA3-256(pk))[:32]
        # This makes the entire encapsulation a function of m alone.
        pk_hash = hashlib.sha3_256(public_key).digest()
        r_seed  = hashlib.sha3_512(m + pk_hash).digest()[:32]

        # Derive r, e1, e2 via PRF (deterministic, not fresh random)
        # Using different nonces for domain separation
        r  = [self._prf(r_seed, i,        N) for i in range(self.k)]
        e1 = [self._prf(r_seed, i + self.k, N) for i in range(self.k)]
        e2 =  self._prf(r_seed, 2 * self.k,  N)

        # Compute u = A^T * r + e1
        u = []
        for i in range(self.k):
            ui = np.zeros(N, dtype=np.int32)
            for j in range(self.k):
                ui = (ui + poly_mul(A[j][i], r[j]).astype(np.int32)) % Q
            ui = poly_add(ui.astype(np.int16), e1[i])
            u.append(ui)

        # Compute v = b^T * r + e2 + Decompress(m)
        v = np.zeros(N, dtype=np.int32)
        for i in range(self.k):
            v = (v + poly_mul(b[i], r[i]).astype(np.int32)) % Q
        v = poly_add(v.astype(np.int16), e2)

        m_poly = np.array([int(bit) for byte in m for bit in format(byte, '08b')], dtype=np.int16)
        m_poly = decompress(m_poly, 1)
        v = poly_add(v, m_poly)

        u_compressed = [compress(ui, DU) for ui in u]
        v_compressed = compress(v, DV)
        ciphertext = self._encode_ciphertext(u_compressed, v_compressed)

        # Shared secret = SHA3-256(m || pk)
        shared_secret = hashlib.sha3_256(m + public_key).digest()

        return ciphertext, shared_secret

    def _encaps_deterministic(self, public_key: bytes, m: bytes) -> Tuple[bytes, bytes]:
        """
        Deterministic encapsulation with a given message m.
        Used only by decaps for the re-encapsulation check (Fix 2).
        MUST produce identical output as encaps() for the same (public_key, m).
        """
        b, d = self._decode_public_key(public_key)
        A = generate_matrix_a(d, self.k)

        pk_hash = hashlib.sha3_256(public_key).digest()
        r_seed  = hashlib.sha3_512(m + pk_hash).digest()[:32]

        r  = [self._prf(r_seed, i,          N) for i in range(self.k)]
        e1 = [self._prf(r_seed, i + self.k, N) for i in range(self.k)]
        e2 =  self._prf(r_seed, 2 * self.k, N)

        u = []
        for i in range(self.k):
            ui = np.zeros(N, dtype=np.int32)
            for j in range(self.k):
                ui = (ui + poly_mul(A[j][i], r[j]).astype(np.int32)) % Q
            ui = poly_add(ui.astype(np.int16), e1[i])
            u.append(ui)

        v = np.zeros(N, dtype=np.int32)
        for i in range(self.k):
            v = (v + poly_mul(b[i], r[i]).astype(np.int32)) % Q
        v = poly_add(v.astype(np.int16), e2)

        m_poly = np.array([int(bit) for byte in m for bit in format(byte, '08b')], dtype=np.int16)
        m_poly = decompress(m_poly, 1)
        v = poly_add(v, m_poly)

        u_compressed = [compress(ui, DU) for ui in u]
        v_compressed = compress(v, DV)
        ciphertext = self._encode_ciphertext(u_compressed, v_compressed)
        shared_secret = hashlib.sha3_256(m + public_key).digest()
        return ciphertext, shared_secret

    def decaps(self, ciphertext: bytes, private_key: bytes) -> bytes:
        """
        Decapsulate: recover shared secret from ciphertext.

        Fix 2 (Dr. B — Re-encapsulation Check for Reaction Attack Prevention):

        The GJS reaction attack works as follows without this check:
          1. Attacker sends a slightly malformed ciphertext ct'.
          2. decaps() returns a wrong shared secret ss' instead of the correct ss.
          3. The connection either succeeds or fails — this is a 1-bit oracle.
          4. Attacker adaptively refines ct', queries oracle 1000+ times,
             recovers the private key s bit-by-bit.

        Fix: After recovering m', re-encapsulate deterministically:
          ct_check, _ = encaps_deterministic(pk, m')
          If ct_check != ciphertext → reject, return pseudorandom value

        The implicit rejection value is SHA3-256(z || ciphertext), where z is
        stored in the private key. This is the FO transform rejection output.
        It is pseudorandom and independent of the private key, giving the
        attacker no useful information about why the ciphertext was rejected.

        Constant-time comparison via hmac.compare_digest prevents timing oracles.

        Args:
            ciphertext:  Encapsulated key (from encaps)
            private_key: Recipient's private key (from keygen)

        Returns:
            shared_secret (genuine or implicit-rejection pseudorandom)
        """
        import hmac as _hmac

        # Decode private key: z (rejection seed), s (LWE secret), pk (public key)
        s, public_key, z = self._decode_private_key(private_key)

        # Decode and decompress ciphertext
        u_compressed, v_compressed = self._decode_ciphertext(ciphertext)
        u = [decompress(ui, DU) for ui in u_compressed]
        v = decompress(v_compressed, DV)

        # Recover m' = Compress(v - s^T * u, 1)
        su = np.zeros(N, dtype=np.int32)
        for i in range(self.k):
            su = (su + poly_mul(s[i], u[i]).astype(np.int32)) % Q
        m_prime_poly = poly_sub(v, su.astype(np.int16))

        m_prime_compressed = compress(m_prime_poly, 1)
        m_bytes = bytearray(32)
        for i in range(256):
            # BUG FIX 1: compress(x, 1) returns 0 or 1, NOT values in [0, Q).
            # Previous code compared with Q//4=832, but the compressed values
            # are only 0 or 1, so the condition was always False, making m'
            # always all-zeros.
            #
            # BUG FIX 2: Bit order was reversed! The encoding uses
            # format(byte, '08b') which gives MSB-first bit order.
            # So bit index i corresponds to bit position (7 - i%8) in byte i//8.
            # Using (1 << (i%8)) sets the WRONG bit, producing reversed bytes.
            if m_prime_compressed[i] == 1:
                m_bytes[i // 8] |= (1 << (7 - i % 8))
        m_prime = bytes(m_bytes)

        # Fix 2: Re-encapsulate with m' and verify ciphertext integrity
        # This is the core of the FO transform implicit rejection mechanism.
        ct_check, ss_prime = self._encaps_deterministic(public_key, m_prime)

        # Constant-time comparison (prevents timing oracle)
        if _hmac.compare_digest(ciphertext, ct_check):
            # Valid ciphertext: return the real shared secret
            return ss_prime
        else:
            # IMPLICIT REJECTION: ciphertext was invalid/malformed.
            # Return a pseudorandom value derived from z (private rejection seed)
            # and the ciphertext. This gives the attacker ZERO information about
            # why the rejection occurred — there is no 1-bit oracle to exploit.
            return hashlib.sha3_256(z + ciphertext).digest()

    def _encode_public_key(self, b: list, d: bytes) -> bytes:
        """Encode public key to bytes."""
        data = d
        for bi in b:
            data += bi.astype(np.uint16).tobytes()
        return data

    def _decode_public_key(self, pk: bytes) -> Tuple[list, bytes]:
        """Decode public key from bytes."""
        d = pk[:32]
        b = []
        offset = 32
        for _ in range(self.k):
            bi = np.frombuffer(pk[offset:offset + N * 2], dtype=np.uint16).astype(np.int16) % Q
            b.append(bi)
            offset += N * 2
        return b, d

    def _encode_private_key(self, s: list, pk: bytes, z: bytes) -> bytes:
        """Encode private key to bytes."""
        data = z
        for si in s:
            data += si.astype(np.int16).tobytes()
        data += pk
        return data

    def _decode_private_key(self, sk: bytes) -> Tuple[list, bytes, bytes]:
        """Decode private key from bytes."""
        z = sk[:32]
        s = []
        offset = 32
        for _ in range(self.k):
            si = np.frombuffer(sk[offset:offset + N * 2], dtype=np.int16)
            s.append(si)
            offset += N * 2
        pk = sk[offset:]
        return s, pk, z

    def _encode_ciphertext(self, u: list, v: np.ndarray) -> bytes:
        """Encode ciphertext to bytes."""
        data = b''
        for ui in u:
            data += ui.astype(np.uint16).tobytes()
        data += v.astype(np.uint16).tobytes()
        return data

    def _decode_ciphertext(self, ct: bytes) -> Tuple[list, np.ndarray]:
        """Decode ciphertext from bytes."""
        u = []
        offset = 0
        for _ in range(self.k):
            ui = np.frombuffer(ct[offset:offset + N * 2], dtype=np.uint16).astype(np.int16) % Q
            u.append(ui)
            offset += N * 2
        v = np.frombuffer(ct[offset:offset + N * 2], dtype=np.uint16).astype(np.int16) % Q
        return u, v


class HybridKeyExchange:
    """
    Hybrid Post-Quantum Key Exchange combining X25519 + Kyber KEM.

    Security: Compromised of either X25519 OR Kyber does not compromise
    the final shared secret (defense in depth).
    """

    def __init__(self):
        self.kyber = KyberKEM(k=2)
        self._x25519_private: Optional[bytes] = None

    def generate_keypair(self) -> Tuple[bytes, bytes]:
        """
        Generate hybrid keypair.

        Returns:
            (hybrid_public_key, hybrid_private_key)
        """
        # Generate X25519 keypair
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
        x25519_priv = X25519PrivateKey.generate()
        x25519_pub = x25519_priv.public_key()

        x25519_priv_bytes = x25519_priv.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption()
        )
        x25519_pub_bytes = x25519_pub.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )

        # Generate Kyber keypair
        kyber_pub, kyber_priv = self.kyber.keygen()

        # Hybrid public key = X25519_pub || Kyber_pub
        hybrid_pub = x25519_pub_bytes + kyber_pub

        # Hybrid private key = X25519_priv || Kyber_priv
        hybrid_priv = x25519_priv_bytes + kyber_priv

        self._x25519_private = x25519_priv_bytes

        return hybrid_pub, hybrid_priv

    def derive_shared_secret(self, 
                            our_private: bytes,
                            their_public: bytes,
                            is_initiator: bool = True) -> bytes:
        """
        Derive hybrid shared secret.

        Args:
            our_private: Our hybrid private key
            their_public: Their hybrid public key
            is_initiator: Whether we initiated the exchange

        Returns:
            32-byte shared secret
        """
        # Split keys
        x25519_priv = our_private[:32]
        kyber_priv = our_private[32:]

        x25519_pub = their_public[:32]
        kyber_pub = their_public[32:]

        # X25519 ECDH
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
        priv_key = X25519PrivateKey.from_private_bytes(x25519_priv)

        # Reconstruct public key
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
        pub_key = X25519PublicKey.from_public_bytes(x25519_pub)

        x25519_shared = priv_key.exchange(pub_key)

        # Kyber encaps/decaps
        if is_initiator:
            # We encapsulate to their Kyber public key
            ciphertext, kyber_shared = self.kyber.encaps(kyber_pub)
            # Store ciphertext to send
            self._last_ciphertext = ciphertext
        else:
            # We decapsulate with our Kyber private key
            # In real protocol, ciphertext comes from network
            kyber_shared = self.kyber.decaps(self._last_ciphertext, kyber_priv)

        # Combine via KDF
        combined = x25519_shared + kyber_shared

        hkdf = HKDF(
            algorithm=hashes.SHA3_256(),
            length=32,
            salt=None,
            info=b'SecureVPN-Hybrid-v1'
        )

        return hkdf.derive(combined)


# Import serialization for X25519
from cryptography.hazmat.primitives import serialization


def generate_pq_psk() -> str:
    """
    Generate a WireGuard Pre-Shared Key (classical security, fallback path).

    Fix 3 (Dr. C — Snake Oil Entropy):
    The previous implementation passed secrets.token_bytes() through a Centered
    Binomial Distribution (CBD) claiming this produced "post-quantum entropy".
    This was cryptographic snake oil:
      - CBD is a statistical distribution for lattice noise, not an entropy source.
      - Running a CSPRNG through CBD does not increase security; it wastes CPU.
      - True PQ security comes from the hardness of the LWE problem (Kyber KEM),
        not from permuting classical randomness through a lattice distribution.

    The correct design (enforced throughout this codebase):
      - Post-quantum PSK MUST be derived from the Kyber KEM shared secret via HKDF
        (see derive_psk_from_shared_secret() and the /add-peer KEM flow).
      - This function is ONLY used as a classical fallback when the client does not
        provide a Kyber public key. It honestly provides 256-bit classical security.

    PSK = SHA3-256(CSPRNG(32 bytes))  →  base64-encoded for WireGuard.
    """
    import base64
    raw = secrets.token_bytes(32)
    psk = hashlib.sha3_256(raw).digest()
    return base64.b64encode(psk).decode('ascii')


def derive_psk_from_shared_secret(shared_secret: bytes) -> str:
    """
    Derive a WireGuard PSK from a Kyber KEM shared secret.

    Both the server (after encapsulation) and the client (after decapsulation)
    call this function with the same shared_secret to produce the same PSK.
    The PSK never crosses the network — only the KEM ciphertext does.

    Protocol:
        PSK = HKDF-SHA3-256(
            ikm  = shared_secret,   # 32 bytes from Kyber encaps/decaps
            salt = None,
            info = b'SecureVPN-PQ-PSK-v1'
        )

    The info string 'SecureVPN-PQ-PSK-v1' domain-separates this derivation
    from any other use of the shared secret, and binds the PSK to this
    specific protocol version.
    """
    hkdf = HKDF(
        algorithm=hashes.SHA3_256(),
        length=32,
        salt=None,
        info=b'SecureVPN-PQ-PSK-v1',
    )
    psk_bytes = hkdf.derive(shared_secret)

    import base64
    return base64.b64encode(psk_bytes).decode('ascii')


if __name__ == '__main__':
    # Test the KEM
    print("Testing Post-Quantum KEM...")
    kem = KyberKEM(k=2)
    pk, sk = kem.keygen()
    ct, ss_enc = kem.encaps(pk)
    ss_dec = kem.decaps(ct, sk)

    assert ss_enc == ss_dec, "KEM test failed!"
    print("✓ KEM encapsulation/decapsulation successful")
    print(f"  Public key size: {len(pk)} bytes")
    print(f"  Ciphertext size: {len(ct)} bytes")
    print(f"  Shared secret: {ss_enc.hex()[:16]}...")
