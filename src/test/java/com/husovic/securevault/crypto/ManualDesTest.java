package com.husovic.securevault.crypto;

import com.husovic.securevault.crypto.symmetric.ManualDes;
import org.junit.jupiter.api.Test;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Dokaz korektnosti ručne DES implementacije: (1) poznati FIPS test-vektor i
 * (2) blok-po-blok poklapanje sa JCE "DES/ECB/NoPadding".
 */
class ManualDesTest {

    @Test
    void knownFipsTestVector() {
        // Kanonski primjer (Grabbe): ključ i tekst -> poznati šifrat.
        long key = 0x133457799BBCDFF1L;
        long plaintext = 0x0123456789ABCDEFL;
        long expected = 0x85E813540F0AB405L;
        assertEquals(expected, ManualDes.encryptBlock(plaintext, key), "DES FIPS test-vektor");
        assertEquals(plaintext, ManualDes.decryptBlock(expected, key), "DES dekripcija test-vektora");
    }

    @Test
    void matchesJceForRandomBlocks() throws Exception {
        SecureRandom rnd = new SecureRandom();
        for (int i = 0; i < 50; i++) {
            byte[] keyBytes = new byte[8];
            byte[] block = new byte[8];
            rnd.nextBytes(keyBytes);
            rnd.nextBytes(block);

            Cipher jce = Cipher.getInstance("DES/ECB/NoPadding");
            jce.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(keyBytes, "DES"));
            byte[] jceOut = jce.doFinal(block);

            byte[] manualOut = ManualDes.encryptEcb(block, ManualDes.bytesToLong(keyBytes, 0));
            assertArrayEquals(jceOut, manualOut, "Ručni DES mora dati isti blok kao JCE");
        }
    }

    @Test
    void ecbRoundTrip() {
        long key = 0x0F1571C947D9E859L;
        byte[] data = "8 bajta!".getBytes(); // tačno 8 bajtova
        byte[] enc = ManualDes.encryptEcb(data, key);
        assertArrayEquals(data, ManualDes.decryptEcb(enc, key));
    }
}
