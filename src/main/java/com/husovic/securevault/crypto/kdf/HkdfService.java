package com.husovic.securevault.crypto.kdf;

import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.generators.HKDFBytesGenerator;
import org.bouncycastle.crypto.params.HKDFParameters;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;

/**
 * HKDF (RFC 5869, HMAC-SHA256) — iz "sirove" zajedničke tajne dobijene DH/ECDH
 * razmjenom izvodi ključ pogodan za AES-GCM. Isti princip (extract-then-expand)
 * koristi TLS 1.3 za izvođenje ključeva sesije (poglavlje o TLS 1.3 key derivation).
 */
@Service
public class HkdfService {

    /**
     * @param sharedSecret  ulazni materijal (IKM) — npr. ECDH zajednička tajna
     * @param salt          opciona so (može biti {@code null})
     * @param info          kontekstualna oznaka koja veže ključ za namjenu
     * @param outLenBytes   dužina izvedenog ključa u bajtovima (npr. 32 za AES-256)
     */
    public byte[] derive(byte[] sharedSecret, byte[] salt, String info, int outLenBytes) {
        HKDFBytesGenerator hkdf = new HKDFBytesGenerator(new SHA256Digest());
        byte[] infoBytes = info == null ? new byte[0] : info.getBytes(StandardCharsets.UTF_8);
        hkdf.init(new HKDFParameters(sharedSecret, salt, infoBytes));
        byte[] out = new byte[outLenBytes];
        hkdf.generateBytes(out, 0, outLenBytes);
        return out;
    }

    /** Pogodnost: izvodi 32-bajtni (AES-256) ključ sesije. */
    public byte[] deriveAes256Key(byte[] sharedSecret, byte[] salt, String info) {
        return derive(sharedSecret, salt, info, 32);
    }
}
