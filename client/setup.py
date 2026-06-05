"""
SecureVPN Client Setup
"""

from setuptools import setup, find_packages

setup(
    name='securevpn-client',
    version='1.0.0',
    description='Post-Quantum WireGuard VPN Client',
    author='Air University NCSA',
    packages=find_packages(),
    install_requires=[
        'requests>=2.31.0',
        'cryptography>=41.0.7',
        'pycryptodome>=3.20.0',
        'numpy>=1.24.3',
        'pystray>=0.19.4',
        'pillow>=10.1.0',
        'scapy>=2.5.0',
        'psutil>=5.9.6',
    ],
    entry_points={
        'console_scripts': [
            'securevpn=securevpn.__main__:main',
        ],
    },
    python_requires='>=3.10',
)
