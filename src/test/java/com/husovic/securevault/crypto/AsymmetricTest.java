package com.husovic.securevault.crypto;

import com.husovic.securevault.crypto.asymmetric.DiffieHellmanService;
import com.husovic.securevault.crypto.asymmetric.EcdhService;
import com.husovic.securevault.crypto.asymmetric.RsaService;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;

import static org.junit.jupiter.api.Assertions.*;

class AsymmetricTest {

    private final RsaService rsa = new RsaService();
    private final DiffieHellmanService dh = new DiffieHellmanService();
    private final EcdhService ecdh = new EcdhService();

    @Test
    void rsaOaepRoundTrip() {
        byte[] msg = "AES ključ sesije".getBytes(StandardCharsets.UTF_8);
        KeyPair kp = rsa.generateKeyPair(2048);
        byte[] ct = rsa.encrypt(msg, kp.getPublic());
        assertArrayEquals(msg, rsa.decrypt(ct, kp.getPrivate()));
    }

    @Test
    void rsaWrongPrivateKeyFails() {
        byte[] msg = "x".getBytes();
        KeyPair a = rsa.generateKeyPair(2048);
        KeyPair b = rsa.generateKeyPair(2048);
        byte[] ct = rsa.encrypt(msg, a.getPublic());
        assertThrows(CryptoException.class, () -> rsa.decrypt(ct, b.getPrivate()));
    }

    @Test
    void rsaPublicKeySerializationRoundTrip() {
        KeyPair kp = rsa.generateKeyPair(2048);
        String b64 = rsa.encodePublicKey(kp.getPublic());
        assertEquals(kp.getPublic(), rsa.decodePublicKey(b64));
    }

    @Test
    void diffieHellmanBothSidesAgree() {
        for (int group : new int[]{2048, 3072}) {
            KeyPair alice = dh.generateKeyPair(group);
            KeyPair bob = dh.generateKeyPair(group);
            byte[] s1 = dh.computeSharedSecret(alice.getPrivate(), bob.getPublic());
            byte[] s2 = dh.computeSharedSecret(bob.getPrivate(), alice.getPublic());
            assertArrayEquals(s1, s2, "DH-" + group + " zajednička tajna");
        }
    }

    @Test
    void ecdhBothSidesAgree() {
        for (String curve : new String[]{EcdhService.CURVE_25519, EcdhService.CURVE_P256}) {
            KeyPair alice = ecdh.generateKeyPair(curve);
            KeyPair bob = ecdh.generateKeyPair(curve);
            byte[] s1 = ecdh.computeSharedSecret(curve, alice.getPrivate(), bob.getPublic());
            byte[] s2 = ecdh.computeSharedSecret(curve, bob.getPrivate(), alice.getPublic());
            assertArrayEquals(s1, s2, "ECDH " + curve + " zajednička tajna");
        }
    }

    @Test
    void ecdhPublicKeySerializationRoundTrip() {
        KeyPair kp = ecdh.generateKeyPair(EcdhService.CURVE_25519);
        String b64 = ecdh.encodePublicKey(kp.getPublic());
        assertEquals(kp.getPublic(), ecdh.decodePublicKey(EcdhService.CURVE_25519, b64));
    }
}
