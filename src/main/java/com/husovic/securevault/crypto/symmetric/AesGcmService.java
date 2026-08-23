package com.husovic.securevault.crypto.symmetric;

import com.husovic.securevault.crypto.CryptoException;
import org.springframework.stereotype.Service;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;

/**
 * AES u GCM modu (autentificirana enkripcija) — koristi se i za enkripciju
 * fajlova u Vault modulu i kao "moderni" referentni algoritam u benchmarku.
 *
 * <p>GCM zahtijeva jedinstven nonce po ključu; ovdje generišemo 96-bitni
 * slučajni nonce po svakoj enkripciji. Tag je 128-bitni.</p>
 */
@Service
public class AesGcmService implements SymmetricCipherService {

    public static final int GCM_NONCE_BYTES = 12;   // 96 bita — preporuka za GCM
    public static final int GCM_TAG_BITS = 128;

    private final SecureRandom random = new SecureRandom();

    @Override
    public String algorithm() {
        return "AES";
    }

    @Override
    public int[] supportedKeySizes() {
        return new int[]{128, 192, 256};
    }

    @Override
    public SecretKey generateKey(int keySizeBits) {
        try {
            KeyGenerator kg = KeyGenerator.getInstance("AES");
            kg.init(keySizeBits, random);
            return kg.generateKey();
        } catch (Exception e) {
            throw new CryptoException("Ne mogu generisati AES ključ (" + keySizeBits + " bita)", e);
        }
    }

    /** Rekonstruiše AES ključ iz sirovih bajtova (npr. izvedenih iz HKDF-a). */
    public SecretKey keyFromBytes(byte[] keyBytes) {
        return new SecretKeySpec(keyBytes, "AES");
    }

    @Override
    public CipherResult encrypt(byte[] plaintext, SecretKey key) {
        try {
            byte[] nonce = new byte[GCM_NONCE_BYTES];
            random.nextBytes(nonce);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(GCM_TAG_BITS, nonce));
            byte[] ct = cipher.doFinal(plaintext);
            return new CipherResult(nonce, ct);
        } catch (Exception e) {
            throw new CryptoException("AES-GCM enkripcija nije uspjela", e);
        }
    }

    @Override
    public byte[] decrypt(CipherResult ciphertext, SecretKey key) {
        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(GCM_TAG_BITS, ciphertext.iv()));
            return cipher.doFinal(ciphertext.ciphertext());
        } catch (Exception e) {
            throw new CryptoException("AES-GCM dekripcija nije uspjela (pogrešan ključ ili narušen integritet)", e);
        }
    }
}
