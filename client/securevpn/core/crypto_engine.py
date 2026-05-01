"""
SecureVPN Client Crypto Engine
Post-Quantum Cryptography with Hybrid Key Exchange.
"""

import os
import sys
import json
import base64
import hashlib
import secrets
import platform
from typing import Tuple, Optional, Dict
from pathlib import Path

import numpy as np
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey

# Kyber-512 security parameters
N = 256
Q = 3329
ETA = 2


class SecureMemory:
    """Secure memory management for sensitive data."""

    @staticmethod
    def wipe(data: bytearray) -> None:
        """Securely wipe bytearray."""
        for i in range(len(data)):
            data[i] = 0

    @staticmethod
    def secure_delete(path: Path) -> None:
        """Securely delete file by overwriting then removing."""
        if not path.exists():
            return

        size = path.stat().st_size
        with open(path, 'r+b') as f:
            f.write(os.urandom(size))
            f.flush()
            os.fsync(f.fileno())

        path.unlink()


class DPAPIStorage:
    """
    Windows Data Protection API for secure key storage.
    Falls back to encrypted file on non-Windows.
    """

    def __init__(self, app_dir: Path):
        self.app_dir = app_dir
        self.storage_file = app_dir / 'secure_storage.enc'
        self._is_windows = platform.system() == 'Windows'
        self._fallback_key = None

    def _get_fallback_key(self) -> bytes:
        """Get or create fallback encryption key using OS Keyring."""
        if self._fallback_key is not None:
            return self._fallback_key

        try:
            import keyring
            encoded_key = keyring.get_password("SecureVPN", "master_key")
            if encoded_key:
                self._fallback_key = base64.b64decode(encoded_key)
                return self._fallback_key
            else:
                self._fallback_key = os.urandom(32)
                keyring.set_password("SecureVPN", "master_key", base64.b64encode(self._fallback_key).decode())
                return self._fallback_key
        except Exception:
            pass

        from pathlib import Path
        ssh_dir = Path.home() / '.ssh'
        ssh_dir.mkdir(mode=0o700, exist_ok=True)
        key_file = ssh_dir / 'securevpn_master.key'

        if key_file.exists():
            self._fallback_key = base64.b64decode(key_file.read_text())
        else:
            self._fallback_key = os.urandom(32)
            key_file.write_text(base64.b64encode(self._fallback_key).decode())
            os.chmod(key_file, 0o600)

        return self._fallback_key

    def encrypt(self, data: bytes) -> bytes:
        """Encrypt data using platform-specific method."""
        if self._is_windows:
            try:
                import win32crypt
                return win32crypt.CryptProtectData(
                    data, "SecureVPN", None, None, None, 0
                )
            except ImportError:
                pass

        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        key = self._get_fallback_key()
        nonce = os.urandom(12)
        aesgcm = AESGCM(key)
        ciphertext = aesgcm.encrypt(nonce, data, None)
        return nonce + ciphertext

    def decrypt(self, data: bytes) -> bytes:
        """Decrypt data."""
        if self._is_windows:
            try:
                import win32crypt
                _, decrypted = win32crypt.CryptUnprotectData(
                    data, None, None, None, 0
                )
                return decrypted
            except ImportError:
                pass

        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        key = self._get_fallback_key()
        nonce = data[:12]
        ciphertext = data[12:]
        aesgcm = AESGCM(key)
        return aesgcm.decrypt(nonce, ciphertext, None)

    def store(self, key: str, value: bytes) -> None:
        """Store encrypted value."""
        self.app_dir.mkdir(parents=True, exist_ok=True)

        data = {}
        if self.storage_file.exists():
            try:
                encrypted = self.storage_file.read_bytes()
                decrypted = self.decrypt(encrypted)
                data = json.loads(decrypted)
            except Exception:
                data = {}

        data[key] = base64.b64encode(value).decode()

        encrypted = self.encrypt(json.dumps(data).encode())
        self.storage_file.write_bytes(encrypted)
        os.chmod(self.storage_file, 0o600)

    def retrieve(self, key: str) -> Optional[bytes]:
        """Retrieve decrypted value."""
        if not self.storage_file.exists():
            return None

        try:
            encrypted = self.storage_file.read_bytes()
            decrypted = self.decrypt(encrypted)
            data = json.loads(decrypted)

            if key in data:
                return base64.b64decode(data[key])
            return None
        except Exception:
            return None


class PostQuantumKEM:
    """CRYSTALS-Kyber-inspired Key Encapsulation Mechanism."""

    def __init__(self, k: int = 2):
        self.k = k

    def _cbd(self, eta: int, length: int) -> np.ndarray:
        """
        Centered binomial distribution for keygen secret/error sampling.

        Uses np.unpackbits for bit-level sampling, giving the correct
        coefficient range {-eta,...,eta} = {-2,...,2}.
        """
        buf = np.frombuffer(secrets.token_bytes(length * eta * 2), dtype=np.uint8)
        buf = buf.reshape(length, eta * 2)
        a = np.unpackbits(buf[:, :eta].view(np.uint8)).reshape(length, eta * 8)[:, :eta].sum(axis=1)
        b = np.unpackbits(buf[:, eta:2*eta].view(np.uint8)).reshape(length, eta * 8)[:, :eta].sum(axis=1)
        return (a - b).astype(np.int16)

    def _prf(self, seed: bytes, nonce: int, length: int) -> np.ndarray:
        """
        Pseudo-Random Function for deterministic noise sampling in encaps().

        PRF(seed, nonce) = SHAKE-256(seed || nonce)[0 : length * ETA * 2]
        Both client and server must use the identical PRF so that
        _encaps_deterministic() in decaps() reproduces the same ciphertext.
        """
        xof = hashlib.shake_256(seed + bytes([nonce]))
        raw = np.frombuffer(xof.digest(length * ETA * 2), dtype=np.uint8)
        raw = raw[:length * ETA * 2].reshape(length, ETA * 2)
        a = np.unpackbits(raw[:, :ETA].view(np.uint8)).reshape(length, ETA * 8)[:, :ETA].sum(axis=1)
        b = np.unpackbits(raw[:, ETA:ETA*2].view(np.uint8)).reshape(length, ETA * 8)[:, :ETA].sum(axis=1)
        return (a - b).astype(np.int16)

    def _poly_mul(self, a: np.ndarray, b: np.ndarray) -> np.ndarray:
        """Polynomial multiplication in R_q."""
        n = len(a)
        result = np.zeros(n, dtype=np.int32)
        for i in range(n):
            for j in range(n):
                if i + j < n:
                    result[i + j] = (result[i + j] + int(a[i]) * int(b[j])) % Q
                else:
                    result[i + j - n] = (result[i + j - n] - int(a[i]) * int(b[j])) % Q
        return result.astype(np.int16)

    def _generate_a(self, seed: bytes, k: int) -> list:
        """
        Generate public matrix A using SHAKE-128 XOF (per FIPS 203).

        All bytes are requested in a single xof.digest() call because
        hashlib.shake_128.digest(n) always returns from byte 0 — calling
        it multiple times produces overlapping (not extended) output.
        """
        import hashlib
        A = []
        for i in range(k):
            row = []
            for j in range(k):
                xof = hashlib.shake_128(seed + bytes([i, j]))
                poly = np.zeros(N, dtype=np.int16)
                count = 0
                buf_size = N * 3
                raw = bytearray(xof.digest(buf_size))
                idx = 0
                while count < N:
                    if idx + 3 > len(raw):
                        buf_size *= 2
                        raw = bytearray(xof.digest(buf_size))
                        idx = 0
                    b0, b1, b2 = raw[idx], raw[idx + 1], raw[idx + 2]
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

    def _compress(self, x: np.ndarray, d: int) -> np.ndarray:
        return np.round((2**d / Q) * x.astype(np.float64)).astype(np.int16) % (2**d)

    def _decompress(self, x: np.ndarray, d: int) -> np.ndarray:
        return np.round((Q / 2**d) * x.astype(np.float64)).astype(np.int16) % Q

    def keygen(self) -> Tuple[bytes, bytes]:
        """Generate keypair."""
        d = secrets.token_bytes(32)
        z = secrets.token_bytes(32)

        A = self._generate_a(d, self.k)
        s = [self._cbd(ETA, N) for _ in range(self.k)]
        e = [self._cbd(ETA, N) for _ in range(self.k)]

        b = []
        for i in range(self.k):
            bi = np.zeros(N, dtype=np.int32)
            for j in range(self.k):
                bi = (bi + self._poly_mul(A[i][j], s[j]).astype(np.int32)) % Q
            bi = ((bi.astype(np.int32) + e[i].astype(np.int32)) % Q).astype(np.int16)
            b.append(bi)

        pk = d + b''.join([bi.astype(np.uint16).tobytes() for bi in b])
        sk = z + b''.join([si.astype(np.int16).tobytes() for si in s]) + pk

        return pk, sk

    def encaps(self, pk: bytes) -> Tuple[bytes, bytes]:
        """
        Encapsulate — FO Transform (IND-CCA2).

        Encapsulation is deterministic:
          r_seed = SHA3-512(m || SHA3-256(pk))[:32]
          r, e1, e2 = PRF(r_seed, nonce)

        This allows decaps() to re-run encapsulation and verify the
        ciphertext matches (reaction attack prevention).
        """
        d = pk[:32]
        b = []
        offset = 32
        for _ in range(self.k):
            bi = np.frombuffer(pk[offset:offset + N * 2], dtype=np.uint16).astype(np.int16) % Q
            b.append(bi)
            offset += N * 2

        A = self._generate_a(d, self.k)

        m = secrets.token_bytes(32)

        pk_hash = hashlib.sha3_256(pk).digest()
        r_seed  = hashlib.sha3_512(m + pk_hash).digest()[:32]

        r  = [self._prf(r_seed, i,          N) for i in range(self.k)]
        e1 = [self._prf(r_seed, i + self.k, N) for i in range(self.k)]
        e2 =  self._prf(r_seed, 2 * self.k, N)

        u = []
        for i in range(self.k):
            ui = np.zeros(N, dtype=np.int32)
            for j in range(self.k):
                ui = (ui + self._poly_mul(A[j][i], r[j]).astype(np.int32)) % Q
            ui = ((ui.astype(np.int32) + e1[i].astype(np.int32)) % Q).astype(np.int16)
            u.append(ui)

        v = np.zeros(N, dtype=np.int32)
        for i in range(self.k):
            v = (v + self._poly_mul(b[i], r[i]).astype(np.int32)) % Q
        v = ((v.astype(np.int32) + e2.astype(np.int32)) % Q).astype(np.int16)

        m_poly = np.array([int(bit) for byte in m for bit in format(byte, '08b')], dtype=np.int16)
        m_poly = self._decompress(m_poly, 1)
        v = ((v.astype(np.int32) + m_poly.astype(np.int32)) % Q).astype(np.int16)

        u_comp = [self._compress(ui, 10) for ui in u]
        v_comp = self._compress(v, 4)

        ct = b''.join([ui.astype(np.uint16).tobytes() for ui in u_comp]) + v_comp.astype(np.uint16).tobytes()
        ss = hashlib.sha3_256(m + pk).digest()

        return ct, ss

    def _encaps_deterministic(self, pk: bytes, m: bytes) -> Tuple[bytes, bytes]:
        """
        Re-encapsulate with given m. Used only by decaps() for the integrity check.
        Must be byte-for-byte identical to encaps() given the same (pk, m).
        """
        d = pk[:32]
        b = []
        offset = 32
        for _ in range(self.k):
            bi = np.frombuffer(pk[offset:offset + N * 2], dtype=np.uint16).astype(np.int16) % Q
            b.append(bi)
            offset += N * 2

        A = self._generate_a(d, self.k)

        pk_hash = hashlib.sha3_256(pk).digest()
        r_seed  = hashlib.sha3_512(m + pk_hash).digest()[:32]

        r  = [self._prf(r_seed, i,          N) for i in range(self.k)]
        e1 = [self._prf(r_seed, i + self.k, N) for i in range(self.k)]
        e2 =  self._prf(r_seed, 2 * self.k, N)

        u = []
        for i in range(self.k):
            ui = np.zeros(N, dtype=np.int32)
            for j in range(self.k):
                ui = (ui + self._poly_mul(A[j][i], r[j]).astype(np.int32)) % Q
            ui = ((ui.astype(np.int32) + e1[i].astype(np.int32)) % Q).astype(np.int16)
            u.append(ui)

        v = np.zeros(N, dtype=np.int32)
        for i in range(self.k):
            v = (v + self._poly_mul(b[i], r[i]).astype(np.int32)) % Q
        v = ((v.astype(np.int32) + e2.astype(np.int32)) % Q).astype(np.int16)

        m_poly = np.array([int(bit) for byte in m for bit in format(byte, '08b')], dtype=np.int16)
        m_poly = self._decompress(m_poly, 1)
        v = ((v.astype(np.int32) + m_poly.astype(np.int32)) % Q).astype(np.int16)

        u_comp = [self._compress(ui, 10) for ui in u]
        v_comp = self._compress(v, 4)

        ct = b''.join([ui.astype(np.uint16).tobytes() for ui in u_comp]) + v_comp.astype(np.uint16).tobytes()
        ss = hashlib.sha3_256(m + pk).digest()
        return ct, ss

    def decaps(self, ct: bytes, sk: bytes) -> bytes:
        """
        Decapsulate with re-encapsulation integrity check (reaction attack prevention).

        Without this check a GJS-style reaction attack can recover the private key
        by sending malformed ciphertexts and observing whether the handshake succeeds.

        Steps:
          1. Recover m' from ciphertext
          2. Re-encapsulate deterministically with m', compare ct_check == ct
          3. Valid: return real shared secret
          4. Invalid: return SHA3-256(z || ct) — pseudorandom implicit rejection
        """
        import hmac as _hmac

        z = sk[:32]
        s = []
        offset = 32
        for _ in range(self.k):
            si = np.frombuffer(sk[offset:offset + N * 2], dtype=np.int16)
            s.append(si)
            offset += N * 2
        pk = sk[offset:]

        u_comp = []
        offset = 0
        for _ in range(self.k):
            ui = np.frombuffer(ct[offset:offset + N * 2], dtype=np.uint16).astype(np.int16) % Q
            u_comp.append(ui)
            offset += N * 2
        v_comp = np.frombuffer(ct[offset:offset + N * 2], dtype=np.uint16).astype(np.int16) % Q

        u = [self._decompress(ui, 10) for ui in u_comp]
        v = self._decompress(v_comp, 4)

        su = np.zeros(N, dtype=np.int32)
        for i in range(self.k):
            su = (su + self._poly_mul(s[i], u[i]).astype(np.int32)) % Q
        m_prime_poly = ((v.astype(np.int32) - su.astype(np.int32)) % Q).astype(np.int16)

        m_comp = self._compress(m_prime_poly, 1)
        m_bytes = bytearray(32)
        for i in range(256):
            # compress(x, 1) returns 0 or 1.
            # Bit order: format(byte,'08b') is MSB-first, so bit i maps to (7 - i%8) in byte i//8.
            if m_comp[i] == 1:
                m_bytes[i // 8] |= (1 << (7 - i % 8))
        m_prime = bytes(m_bytes)

        ct_check, ss_prime = self._encaps_deterministic(pk, m_prime)

        if _hmac.compare_digest(ct, ct_check):
            return ss_prime
        else:
            # Implicit rejection — attacker learns nothing from the response
            return hashlib.sha3_256(z + ct).digest()


class HybridCryptoEngine:
    """Hybrid Post-Quantum Key Exchange Engine (X25519 + Kyber KEM)."""

    def __init__(self, app_dir: Path):
        self.app_dir = app_dir
        self.storage = DPAPIStorage(app_dir)
        self.kem = PostQuantumKEM(k=2)

    def generate_keypair(self) -> Tuple[bytes, bytes]:
        """Generate hybrid keypair."""
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

        kyber_pub, kyber_priv = self.kem.keygen()

        hybrid_pub = x25519_pub_bytes + kyber_pub
        hybrid_priv = x25519_priv_bytes + kyber_priv

        return hybrid_pub, hybrid_priv

    def derive_shared_secret(self,
                            our_priv: bytes,
                            their_pub: bytes,
                            is_initiator: bool = True) -> bytes:
        """Derive hybrid shared secret."""
        x25519_priv = our_priv[:32]
        kyber_priv = our_priv[32:]

        x25519_pub = their_pub[:32]
        kyber_pub = their_pub[32:]

        priv_key = X25519PrivateKey.from_private_bytes(x25519_priv)
        pub_key = X25519PublicKey.from_public_bytes(x25519_pub)
        x25519_shared = priv_key.exchange(pub_key)

        if is_initiator:
            ct, kyber_shared = self.kem.encaps(kyber_pub)
            self._last_ciphertext = ct
        else:
            kyber_shared = self.kem.decaps(self._last_ciphertext, kyber_priv)

        combined = x25519_shared + kyber_shared

        hkdf = HKDF(
            algorithm=hashes.SHA3_256(),
            length=32,
            salt=None,
            info=b'SecureVPN-Hybrid-v1'
        )

        return hkdf.derive(combined)

    def generate_wireguard_keys(self) -> Tuple[str, str]:
        """Generate WireGuard-compatible keypair using wg CLI."""
        import subprocess

        priv = subprocess.run(
            ['wg', 'genkey'], capture_output=True, text=True, check=True
        ).stdout.strip()

        pub = subprocess.run(
            ['wg', 'pubkey'], input=priv, capture_output=True, text=True, check=True
        ).stdout.strip()

        return priv, pub

    def generate_kyber_keypair(self) -> Tuple[bytes, bytes]:
        """
        Generate a Kyber-512 keypair for the hybrid PQ PSK flow.

        Returns:
            (kyber_public_key_bytes, kyber_private_key_bytes)

        The public key is sent to the server. The private key never leaves
        the client — stored encrypted via DPAPI, used only for decapsulation.
        """
        return self.kem.keygen()

    def kyber_decaps_psk(self, ciphertext: bytes, kyber_sk: bytes) -> str:
        """
        Decapsulate the server's KEM ciphertext and derive a WireGuard PSK.

        Protocol:
          Server: ciphertext, shared_secret = Kyber.encaps(client_pk)
          Client: shared_secret = Kyber.decaps(ciphertext, client_sk)
          Both:   PSK = HKDF-SHA3-256(shared_secret, info=SecureVPN-PQ-PSK-v1)

        The PSK is base64-encoded for WireGuard. Neither the raw shared_secret
        nor the Kyber private key ever cross the network.
        """
        shared_secret = self.kem.decaps(ciphertext, kyber_sk)

        hkdf = HKDF(
            algorithm=hashes.SHA3_256(),
            length=32,
            salt=None,
            info=b'SecureVPN-PQ-PSK-v1',
        )
        psk_bytes = hkdf.derive(shared_secret)
        return base64.b64encode(psk_bytes).decode('ascii')

    def generate_pq_psk(self) -> str:
        """
        Generate a WireGuard PSK for the classical fallback path.

        Called only when the server does not return a KEM ciphertext.
        Post-quantum security is only achieved via the Kyber KEM path.
        """
        raw = secrets.token_bytes(32)
        psk = hashlib.sha3_256(raw).digest()
        return base64.b64encode(psk).decode('ascii')

    def secure_store_key(self, name: str, key_data: Dict) -> None:
        """Securely store key material."""
        serialized = json.dumps(key_data).encode()
        self.storage.store(f"keys_{name}", serialized)

    def secure_load_key(self, name: str) -> Optional[Dict]:
        """Load key material."""
        data = self.storage.retrieve(f"keys_{name}")
        if data:
            return json.loads(data)
        return None
