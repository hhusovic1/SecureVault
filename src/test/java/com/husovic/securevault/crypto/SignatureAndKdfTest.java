package com.husovic.securevault.crypto;

import com.husovic.securevault.crypto.asymmetric.RsaService;
import com.husovic.securevault.crypto.kdf.HkdfService;
import com.husovic.securevault.crypto.signature.CertificateService;
import com.husovic.securevault.crypto.signature.EcdsaSignatureService;
import com.husovic.securevault.crypto.signature.RsaSignatureService;
import com.husovic.securevault.crypto.signature.SimpleCertificate;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;

import static org.junit.jupiter.api.Assertions.*;

class SignatureAndKdfTest {

    private final RsaService rsa = new RsaService();
    private final RsaSignatureService rsaSig = new RsaSignatureService();
    private final EcdsaSignatureService ecdsa = new EcdsaSignatureService();
    private final CertificateService certService = new CertificateService(rsaSig, rsa);
    private final HkdfService hkdf = new HkdfService();

    private final byte[] data = "podaci koji se potpisuju".getBytes(StandardCharsets.UTF_8);

    @Test
    void rsaPssSignVerify() {
        KeyPair kp = rsa.generateKeyPair(2048);
        byte[] sig = rsaSig.sign(data, kp.getPrivate());
        assertTrue(rsaSig.verify(data, sig, kp.getPublic()));
        data[0] ^= 0x01;
        assertFalse(rsaSig.verify(data, sig, kp.getPublic()), "izmijenjeni podaci ne smiju proći");
    }

    @Test
    void ecdsaSignVerify() {
        KeyPair kp = ecdsa.generateKeyPair();
        byte[] payload = "poruka".getBytes();
        byte[] sig = ecdsa.sign(payload, kp.getPrivate());
        assertTrue(ecdsa.verify(payload, sig, kp.getPublic()));
        byte[] tampered = "poruXa".getBytes();
        assertFalse(ecdsa.verify(tampered, sig, kp.getPublic()));
    }

    @Test
    void certificateIssueAndVerify() {
        KeyPair identity = rsa.generateKeyPair(2048);
        KeyPair subjectKey = rsa.generateKeyPair(2048);
        SimpleCertificate cert = certService.issue(
                "SecureVault Server", subjectKey.getPublic(), "SecureVault CA", identity.getPrivate());
        assertTrue(certService.verify(cert, identity.getPublic()));

        KeyPair attacker = rsa.generateKeyPair(2048);
        assertFalse(certService.verify(cert, attacker.getPublic()), "tuđi ključ ne smije verifikovati");
    }

    @Test
    void hkdfDeterministicAndContextSeparated() {
        byte[] secret = "sirova-dh-tajna".getBytes();
        byte[] k1 = hkdf.deriveAes256Key(secret, null, "securevault session key");
        byte[] k2 = hkdf.deriveAes256Key(secret, null, "securevault session key");
        assertArrayEquals(k1, k2, "isti ulaz -> isti ključ");
        assertEquals(32, k1.length);

        byte[] k3 = hkdf.deriveAes256Key(secret, null, "druga namjena");
        assertFalse(java.util.Arrays.equals(k1, k3), "različit info -> različit ključ");
    }
}
