package com.husovic.securevault.crypto.symmetric;

import com.husovic.securevault.crypto.CryptoException;
import org.springframework.stereotype.Service;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.security.SecureRandom;

/**
 * Klasični DES preko JCE (CBC/PKCS5Padding). Efektivna dužina ključa je 56 bita
 * (8 paritetnih bitova se ignoriše) — u benchmarku i sigurnosnoj analizi služi kao
 * primjer algoritma koji je danas probijiv brute-force napadom.
 */
@Service
public class DesService implements SymmetricCipherService {

    private static final int BLOCK_BYTES = 8; // 64-bitni blok / IV
    private final SecureRandom random = new SecureRandom();

    @Override
    public String algorithm() {
        return "DES";
    }

    @Override
    public int[] supportedKeySizes() {
        return new int[]{56};
    }

    @Override
    public SecretKey generateKey(int keySizeBits) {
        try {
            KeyGenerator kg = KeyGenerator.getInstance("DES");
            kg.init(random);
            return kg.generateKey();
        } catch (Exception e) {
            throw new CryptoException("Ne mogu generisati DES ključ", e);
        }
    }

    @Override
    public CipherResult encrypt(byte[] plaintext, SecretKey key) {
        try {
            byte[] iv = new byte[BLOCK_BYTES];
            random.nextBytes(iv);
            Cipher cipher = Cipher.getInstance("DES/CBC/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));
            return new CipherResult(iv, cipher.doFinal(plaintext));
        } catch (Exception e) {
            throw new CryptoException("DES enkripcija nije uspjela", e);
        }
    }

    @Override
    public byte[] decrypt(CipherResult ciphertext, SecretKey key) {
        try {
            Cipher cipher = Cipher.getInstance("DES/CBC/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(ciphertext.iv()));
            return cipher.doFinal(ciphertext.ciphertext());
        } catch (Exception e) {
            throw new CryptoException("DES dekripcija nije uspjela (pogrešan ključ?)", e);
        }
    }
}
