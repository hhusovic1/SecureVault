#!/usr/bin/env python3
"""
Referentni klijent za SecureVault hibridni handshake.

Izvodi kompletan tok:
  1. dohvat certifikata servera,
  2. init (razmjena efemernih ECDH ključeva),
  3. verifikacija potpisa servera,
  4. izvođenje istog AES-256 ključa (HKDF),
  5. finish (AES-GCM "Finished" poruka),
  6. upload + download fajla i provjera round-trip-a.

Kripto konvencije su namjerno usklađene sa serverskom (Java/Bouncy Castle):
  - ECDH javni ključ: X.509 SubjectPublicKeyInfo, DER, Base64
  - HKDF: HMAC-SHA256, salt=None, info = hkdfInfo string, dužina 32 B
  - AES-GCM: 12-bajtni nonce, 128-bitni tag zalijepljen na kraj šifrata

Pokretanje:
    pip install -r requirements.txt
    python securevault_client.py --url http://localhost:8080 --curve X25519
"""
import argparse
import base64
import os
import sys

import requests
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


def b64e(data: bytes) -> str:
    return base64.b64encode(data).decode()


def b64d(text: str) -> bytes:
    return base64.b64decode(text)


def gen_keypair(curve: str):
    """Vraća (private_key, public_der_base64) za odabranu krivu."""
    if curve.upper() in ("X25519", "CURVE25519", "25519"):
        priv = x25519.X25519PrivateKey.generate()
    elif curve.upper() in ("P-256", "P256", "SECP256R1"):
        priv = ec.generate_private_key(ec.SECP256R1())
    else:
        raise ValueError(f"Nepoznata kriva: {curve}")
    pub_der = priv.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return priv, b64e(pub_der)


def compute_shared(curve: str, priv, server_pub_b64: str) -> bytes:
    server_pub = serialization.load_der_public_key(b64d(server_pub_b64))
    if curve.upper() in ("X25519", "CURVE25519", "25519"):
        return priv.exchange(server_pub)
    return priv.exchange(ec.ECDH(), server_pub)


def hkdf_aes256(shared: bytes, info: str) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
                info=info.encode()).derive(shared)


def handshake(base_url: str, curve: str) -> tuple[str, bytes]:
    # 1. certifikat servera (u realnom scenariju bi se "pinovao" unaprijed)
    cert = requests.get(f"{base_url}/api/handshake/server-identity", timeout=10).json()
    print(f"[i] Server: {cert['subject']} (izdavalac: {cert['issuer']})")

    # 2. init
    priv, client_pub = gen_keypair(curve)
    init = requests.post(f"{base_url}/api/handshake/init",
                         json={"curve": curve, "clientEcdhPublicKey": client_pub},
                         timeout=10).json()
    session_id = init["sessionId"]
    print(f"[i] Sesija: {session_id}")

    # 3. verifikacija potpisa servera (RSA-PSS nad transkriptom)
    identity_pub = serialization.load_der_public_key(b64d(cert["publicKeyBase64"]))
    from cryptography.hazmat.primitives.asymmetric import padding
    try:
        identity_pub.verify(
            b64d(init["signatureBase64"]),
            init["transcript"].encode(),
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.DIGEST_LENGTH),
            hashes.SHA256(),
        )
    except InvalidSignature:
        print("[FAIL] Potpis servera NIJE validan — prekidam.", file=sys.stderr)
        sys.exit(1)
    print("[OK] Potpis servera je validan — server autentifikovan.")

    # 4. izvođenje istog AES ključa
    shared = compute_shared(curve, priv, init["serverEcdhPublicKey"])
    key = hkdf_aes256(shared, init["hkdfInfo"])

    # 5. finish — AES-GCM "Finished" poruka
    finished = f"SecureVault client finished|{session_id}".encode()
    nonce = os.urandom(12)
    ct = AESGCM(key).encrypt(nonce, finished, None)
    fin = requests.post(f"{base_url}/api/handshake/finish",
                        json={"sessionId": session_id,
                              "confirmationIv": b64e(nonce),
                              "confirmationCiphertext": b64e(ct)},
                        timeout=10).json()
    print(f"[OK] {fin.get('message', fin)}")
    return session_id, key


def vault_roundtrip(base_url: str, session_id: str) -> None:
    payload = b"Referentni klijent: povjerljiv sadrzaj fajla."
    files = {"file": ("klijent.txt", payload, "text/plain")}
    meta = requests.post(f"{base_url}/api/vault/{session_id}/upload",
                         files=files, timeout=30).json()
    file_id = meta["fileId"]
    print(f"[i] Otpremljen fajl: {file_id} ({meta['plaintextSize']} B)")

    resp = requests.get(f"{base_url}/api/vault/{session_id}/{file_id}/download", timeout=30)
    ok = resp.content == payload
    print(f"[{'OK' if ok else 'FAIL'}] Download round-trip: {'USPJEH' if ok else 'NEUSPJEH'}")


def main() -> None:
    ap = argparse.ArgumentParser(description="SecureVault referentni klijent")
    ap.add_argument("--url", default="http://localhost:8080", help="bazni URL servera")
    ap.add_argument("--curve", default="X25519", help="ECDH kriva: X25519 ili P-256")
    args = ap.parse_args()

    try:  # čist UTF-8 ispis i na Windows konzoli
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:  # noqa: BLE001
        pass

    session_id, _key = handshake(args.url, args.curve)
    vault_roundtrip(args.url, session_id)


if __name__ == "__main__":
    main()
