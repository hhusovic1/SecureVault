package com.husovic.securevault.crypto.asymmetric;

import com.husovic.securevault.config.CryptoConfig;
import com.husovic.securevault.crypto.CryptoException;
import org.springframework.stereotype.Service;

import javax.crypto.KeyAgreement;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

/**
 * ECDH razmjena ključeva nad Curve25519 (X25519) i NIST P-256 (secp256r1).
 * Efemerni ECDH par po sesiji je osnova Perfect Forward Secrecy svojstva
 * hibridnog handshake-a (poglavlje 3.5.2).
 */
@Service
public class EcdhService {

    public static final String CURVE_25519 = "X25519";
    public static final String CURVE_P256 = "P-256";

    static {
        CryptoConfig.ensureProvider();
    }

    public KeyPair generateKeyPair(String curve) {
        try {
            if (CURVE_25519.equalsIgnoreCase(curve)) {
                KeyPairGenerator kpg = KeyPairGenerator.getInstance("X25519", CryptoConfig.BC);
                return kpg.generateKeyPair();
            } else if (CURVE_P256.equalsIgnoreCase(curve)) {
                KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", CryptoConfig.BC);
                kpg.initialize(new ECGenParameterSpec("secp256r1"));
                return kpg.generateKeyPair();
            }
            throw new CryptoException("Nepoznata kriva: " + curve + " (podržano: X25519, P-256)");
        } catch (CryptoException ce) {
            throw ce;
        } catch (Exception e) {
            throw new CryptoException("Ne mogu generisati ECDH par ključeva za krivu " + curve, e);
        }
    }

    public byte[] computeSharedSecret(String curve, PrivateKey ownPrivate, PublicKey otherPublic) {
        try {
            String algo = CURVE_25519.equalsIgnoreCase(curve) ? "X25519" : "ECDH";
            KeyAgreement ka = KeyAgreement.getInstance(algo, CryptoConfig.BC);
            ka.init(ownPrivate);
            ka.doPhase(otherPublic, true);
            return ka.generateSecret();
        } catch (Exception e) {
            throw new CryptoException("ECDH razmjena nije uspjela (" + curve + ")", e);
        }
    }

    public String encodePublicKey(PublicKey key) {
        return Base64.getEncoder().encodeToString(key.getEncoded());
    }

    public PublicKey decodePublicKey(String curve, String base64) {
        try {
            byte[] der = Base64.getDecoder().decode(base64);
            String algo = CURVE_25519.equalsIgnoreCase(curve) ? "X25519" : "EC";
            return KeyFactory.getInstance(algo, CryptoConfig.BC)
                    .generatePublic(new X509EncodedKeySpec(der));
        } catch (Exception e) {
            throw new CryptoException("Neispravan ECDH javni ključ (" + curve + ")", e);
        }
    }
}
