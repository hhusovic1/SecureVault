package com.husovic.securevault.crypto;

import com.husovic.securevault.crypto.symmetric.AesGcmService;
import com.husovic.securevault.crypto.symmetric.CipherResult;
import com.husovic.securevault.crypto.symmetric.DesService;
import com.husovic.securevault.crypto.symmetric.SymmetricCipherService;
import com.husovic.securevault.crypto.symmetric.TripleDesService;
import org.junit.jupiter.api.Test;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class SymmetricCipherTest {

    private final AesGcmService aes = new AesGcmService();
    private final DesService des = new DesService();
    private final TripleDesService tripleDes = new TripleDesService();

    private final byte[] message = "Tajna poruka za završni rad — SecureVault 🔐".getBytes(StandardCharsets.UTF_8);

    @Test
    void aesRoundTripAllKeySizes() {
        for (int size : aes.supportedKeySizes()) {
            SecretKey key = aes.generateKey(size);
            CipherResult ct = aes.encrypt(message, key);
            assertArrayEquals(message, aes.decrypt(ct, key), "AES-" + size + " round-trip");
        }
    }

    @Test
    void desAnd3desRoundTrip() {
        for (SymmetricCipherService svc : List.of(des, tripleDes)) {
            SecretKey key = svc.generateKey(svc.supportedKeySizes()[0]);
            CipherResult ct = svc.encrypt(message, key);
            assertArrayEquals(message, svc.decrypt(ct, key), svc.algorithm() + " round-trip");
        }
    }

    @Test
    void wrongKeyCannotDecrypt() {
        for (SymmetricCipherService svc : List.<SymmetricCipherService>of(aes, des, tripleDes)) {
            int size = svc.supportedKeySizes()[0];
            SecretKey k1 = svc.generateKey(size);
            SecretKey k2 = svc.generateKey(size);
            CipherResult ct = svc.encrypt(message, k1);
            // Ili baci izuzetak (GCM auth / DES pad), ili vrati nešto što nije original.
            try {
                byte[] out = svc.decrypt(ct, k2);
                assertFalse(java.util.Arrays.equals(message, out),
                        svc.algorithm() + ": tuđi ključ ne smije vratiti original");
            } catch (CryptoException expected) {
                // očekivano za GCM (auth tag) i najčešće za CBC padding
            }
        }
    }

    @Test
    void freshIvPerEncryption() {
        SecretKey key = aes.generateKey(256);
        CipherResult a = aes.encrypt(message, key);
        CipherResult b = aes.encrypt(message, key);
        assertFalse(java.util.Arrays.equals(a.iv(), b.iv()), "IV mora biti svjež po enkripciji");
        assertFalse(java.util.Arrays.equals(a.ciphertext(), b.ciphertext()), "šifrat mora biti različit");
    }
}
