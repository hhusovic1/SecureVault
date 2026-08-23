package com.husovic.securevault.crypto.asymmetric;

import com.husovic.securevault.config.CryptoConfig;
import com.husovic.securevault.crypto.CryptoException;
import org.springframework.stereotype.Service;

import javax.crypto.Cipher;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

/**
 * RSA sa OAEP paddingom (SHA-256) preko Bouncy Castle-a. OAEP je sigurna,
 * randomizovana šema — za razliku od PKCS#1 v1.5 varijante koja je namjerno
 * izolovana u {@code vuln} paketu radi demonstracije padding oracle napada.
 */
@Service
public class RsaService {

    /** Transformacija za sigurnu (OAEP) enkripciju. */
    public static final String OAEP = "RSA/NONE/OAEPWithSHA-256AndMGF1Padding";

    static {
        CryptoConfig.ensureProvider();
    }

    public KeyPair generateKeyPair(int keySizeBits) {
        try {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", CryptoConfig.BC);
            kpg.initialize(keySizeBits);
            return kpg.generateKeyPair();
        } catch (Exception e) {
            throw new CryptoException("Ne mogu generisati RSA par ključeva (" + keySizeBits + " bita)", e);
        }
    }

    public byte[] encrypt(byte[] plaintext, PublicKey publicKey) {
        try {
            Cipher cipher = Cipher.getInstance(OAEP, CryptoConfig.BC);
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            return cipher.doFinal(plaintext);
        } catch (Exception e) {
            throw new CryptoException("RSA-OAEP enkripcija nije uspjela", e);
        }
    }

    public byte[] decrypt(byte[] ciphertext, PrivateKey privateKey) {
        try {
            Cipher cipher = Cipher.getInstance(OAEP, CryptoConfig.BC);
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            return cipher.doFinal(ciphertext);
        } catch (Exception e) {
            throw new CryptoException("RSA-OAEP dekripcija nije uspjela", e);
        }
    }

    // --- Serijalizacija ključeva (za handshake / API) ---

    public String encodePublicKey(PublicKey key) {
        return Base64.getEncoder().encodeToString(key.getEncoded());
    }

    public PublicKey decodePublicKey(String base64) {
        try {
            byte[] der = Base64.getDecoder().decode(base64);
            return KeyFactory.getInstance("RSA", CryptoConfig.BC)
                    .generatePublic(new X509EncodedKeySpec(der));
        } catch (Exception e) {
            throw new CryptoException("Neispravan RSA javni ključ", e);
        }
    }

    public PrivateKey decodePrivateKey(String base64) {
        try {
            byte[] der = Base64.getDecoder().decode(base64);
            return KeyFactory.getInstance("RSA", CryptoConfig.BC)
                    .generatePrivate(new PKCS8EncodedKeySpec(der));
        } catch (Exception e) {
            throw new CryptoException("Neispravan RSA privatni ključ", e);
        }
    }
}
