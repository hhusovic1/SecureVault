package com.husovic.securevault.crypto.signature;

import java.nio.charset.StandardCharsets;
import java.nio.ByteBuffer;

/**
 * Minimalni "certifikat" — POJO koji ilustruje koncept iz poglavlja 3.6.1 bez
 * kompleksnosti punog X.509. Vezuje subjekt za javni ključ, potpisano privatnim
 * ključem izdavaoca. Za samostalno-potpisan certifikat je {@code issuer == subject}.
 *
 * @param subject          ime vlasnika ključa (npr. "SecureVault Server")
 * @param algorithm        algoritam javnog ključa ("RSA", "EC", ...)
 * @param publicKeyBase64  X.509/SubjectPublicKeyInfo javni ključ, Base64
 * @param issuer           ime izdavaoca
 * @param signatureBase64  potpis izdavaoca nad {@link #tbsBytes()}, Base64
 */
public record SimpleCertificate(
        String subject,
        String algorithm,
        String publicKeyBase64,
        String issuer,
        String signatureBase64) {

    /**
     * "To-be-signed" bajtovi — kanonska serijalizacija polja koja se potpisuju.
     * Svako polje je prefiksirano svojom dužinom da se izbjegne dvosmislenost.
     */
    public byte[] tbsBytes() {
        return tbsBytes(subject, algorithm, publicKeyBase64, issuer);
    }

    public static byte[] tbsBytes(String subject, String algorithm, String publicKeyBase64, String issuer) {
        byte[] s = subject.getBytes(StandardCharsets.UTF_8);
        byte[] a = algorithm.getBytes(StandardCharsets.UTF_8);
        byte[] k = publicKeyBase64.getBytes(StandardCharsets.UTF_8);
        byte[] i = issuer.getBytes(StandardCharsets.UTF_8);
        ByteBuffer buf = ByteBuffer.allocate(16 + s.length + a.length + k.length + i.length);
        buf.putInt(s.length).put(s);
        buf.putInt(a.length).put(a);
        buf.putInt(k.length).put(k);
        buf.putInt(i.length).put(i);
        return buf.array();
    }
}
