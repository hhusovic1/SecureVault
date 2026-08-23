import { Injectable } from '@angular/core';

export interface FileMeta {
  fileId: string;
  originalName: string;
  plaintextSize: number;
}

export interface SymmetricResult {
  algorithm: string;
  keySizeBits: number;
  dataSizeKB: number;
  avgEncryptMs: number;
  encryptThroughputMBs: number;
}

export interface BrutePoint {
  keyBits: number;
  elapsedMs: number;
}

const B = {
  enc: (buf: ArrayBuffer) => btoa(String.fromCharCode(...new Uint8Array(buf))),
  dec: (s: string) => Uint8Array.from(atob(s), c => c.charCodeAt(0)).buffer,
};

/**
 * Sva komunikacija sa SecureVault backendom + kompletan hibridni handshake
 * odrađen u browseru preko Web Crypto API-ja (P-256 ECDH + HKDF + AES-GCM +
 * RSA-PSS verifikacija). Izvedeni AES ključ ostaje ovdje u memoriji.
 */
@Injectable({ providedIn: 'root' })
export class SecurevaultService {
  sessionId: string | null = null;
  private aesKey: CryptoKey | null = null;
  private readonly enc = new TextEncoder();

  get established(): boolean {
    return this.sessionId !== null && this.aesKey !== null;
  }

  /** Izvodi cijeli handshake; poziva onStep(indeks, uspjeh) nakon svakog koraka. */
  async handshake(onStep: (i: number, ok: boolean) => void): Promise<void> {
    const CURVE = 'P-256';

    // 1. certifikat + identitetski RSA ključ servera
    const cert = await (await fetch('/api/handshake/server-identity')).json();
    const idKey = await crypto.subtle.importKey('spki', B.dec(cert.publicKeyBase64),
      { name: 'RSA-PSS', hash: 'SHA-256' }, false, ['verify']);
    onStep(0, true);

    // 2. efemerni ECDH par + init
    const kp = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: CURVE }, false, ['deriveBits']);
    const clientPub = B.enc(await crypto.subtle.exportKey('spki', kp.publicKey));
    const init = await (await fetch('/api/handshake/init', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ curve: CURVE, clientEcdhPublicKey: clientPub }),
    })).json();
    onStep(1, true);

    // 3. verifikacija potpisa transkripta (RSA-PSS)
    const sigOk = await crypto.subtle.verify({ name: 'RSA-PSS', saltLength: 32 }, idKey,
      B.dec(init.signatureBase64), this.enc.encode(init.transcript));
    onStep(2, sigOk);
    if (!sigOk) throw new Error('Potpis servera nije validan!');

    // 4. ECDH -> HKDF -> AES-256 ključ (isti kao na serveru)
    const serverPub = await crypto.subtle.importKey('spki', B.dec(init.serverEcdhPublicKey),
      { name: 'ECDH', namedCurve: CURVE }, false, []);
    const shared = await crypto.subtle.deriveBits({ name: 'ECDH', public: serverPub }, kp.privateKey, 256);
    const ikm = await crypto.subtle.importKey('raw', shared, 'HKDF', false, ['deriveBits']);
    const keyBits = await crypto.subtle.deriveBits(
      { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(32), info: this.enc.encode(init.hkdfInfo) },
      ikm, 256);
    const aesKey = await crypto.subtle.importKey('raw', keyBits, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
    onStep(3, true);

    // 5. "Finished" poruka (dokaz posjedovanja ključa)
    const finished = this.enc.encode('SecureVault client finished|' + init.sessionId);
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv, tagLength: 128 }, aesKey, finished);
    const fin = await (await fetch('/api/handshake/finish', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        sessionId: init.sessionId,
        confirmationIv: B.enc(iv.buffer),
        confirmationCiphertext: B.enc(ct),
      }),
    })).json();
    if (fin.status !== 'ESTABLISHED') throw new Error(fin.message || 'finish nije uspio');
    onStep(4, true);

    this.sessionId = init.sessionId;
    this.aesKey = aesKey;
  }

  async listFiles(): Promise<FileMeta[]> {
    return (await fetch(`/api/vault/${this.sessionId}/files`)).json();
  }

  async upload(file: File): Promise<void> {
    const fd = new FormData();
    fd.append('file', file);
    const res = await fetch(`/api/vault/${this.sessionId}/upload`, { method: 'POST', body: fd });
    if (!res.ok) throw new Error('Upload nije uspio (' + res.status + ')');
  }

  async download(fileId: string, name: string): Promise<void> {
    const res = await fetch(`/api/vault/${this.sessionId}/${fileId}/download`);
    if (!res.ok) throw new Error('Download nije uspio');
    const blob = await res.blob();
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = name;
    a.click();
    URL.revokeObjectURL(a.href);
  }

  async benchmarkSymmetric(alg: string, keySize: number, sizeKB: number, reps: number): Promise<SymmetricResult> {
    return (await fetch(
      `/api/benchmark/symmetric?algorithm=${alg}&keySize=${keySize}&dataSizeKB=${sizeKB}&repetitions=${reps}`)).json();
  }

  async bruteScaling(minBits: number, maxBits: number): Promise<BrutePoint[]> {
    return (await fetch(`/api/vuln/des-bruteforce/scaling?minBits=${minBits}&maxBits=${maxBits}`)).json();
  }
}
