package com.husovic.securevault.crypto.symmetric;

import com.husovic.securevault.crypto.CryptoException;
import org.springframework.stereotype.Service;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.security.SecureRandom;

/**
 * 3DES (DESede) preko JCE (CBC/PKCS5Padding). Ključ je 168 bita (3×56), ali zbog
 * meet-in-the-middle napada efektivna sigurnost je ~112 bita. U benchmarku pokazuje
 * karakteristično trostruko sporije šifrovanje u odnosu na jednostruki DES.
 */
@Service
public class TripleDesService implements SymmetricCipherService {

    private static final int BLOCK_BYTES = 8;
    private final SecureRandom random = new SecureRandom();

    @Override
    public String algorithm() {
        return "3DES";
    }

    @Override
    public int[] supportedKeySizes() {
        return new int[]{168};
    }

    @Override
    public SecretKey generateKey(int keySizeBits) {
        try {
            KeyGenerator kg = KeyGenerator.getInstance("DESede");
            kg.init(random);
            return kg.generateKey();
        } catch (Exception e) {
            throw new CryptoException("Ne mogu generisati 3DES ključ", e);
        }
    }

    @Override
    public CipherResult encrypt(byte[] plaintext, SecretKey key) {
        try {
            byte[] iv = new byte[BLOCK_BYTES];
            random.nextBytes(iv);
            Cipher cipher = Cipher.getInstance("DESede/CBC/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));
            return new CipherResult(iv, cipher.doFinal(plaintext));
        } catch (Exception e) {
            throw new CryptoException("3DES enkripcija nije uspjela", e);
        }
    }

    @Override
    public byte[] decrypt(CipherResult ciphertext, SecretKey key) {
        try {
            Cipher cipher = Cipher.getInstance("DESede/CBC/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(ciphertext.iv()));
            return cipher.doFinal(ciphertext.ciphertext());
        } catch (Exception e) {
            throw new CryptoException("3DES dekripcija nije uspjela (pogrešan ključ?)", e);
        }
    }
}
