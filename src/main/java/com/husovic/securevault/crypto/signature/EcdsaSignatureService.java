package com.husovic.securevault.crypto.signature;

import com.husovic.securevault.config.CryptoConfig;
import com.husovic.securevault.crypto.CryptoException;
import org.springframework.stereotype.Service;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;

/**
 * ECDSA potpisi nad P-256 (SHA-256). U poređenju sa RSA daje kraće ključeve i
 * potpise uz ekvivalentan nivo sigurnosti — argument u prilog ECC-a u radu.
 */
@Service
public class EcdsaSignatureService {

    private static final String ALG = "SHA256withECDSA";

    static {
        CryptoConfig.ensureProvider();
    }

    public KeyPair generateKeyPair() {
        try {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", CryptoConfig.BC);
            kpg.initialize(new ECGenParameterSpec("secp256r1"));
            return kpg.generateKeyPair();
        } catch (Exception e) {
            throw new CryptoException("Ne mogu generisati ECDSA par ključeva", e);
        }
    }

    public byte[] sign(byte[] data, PrivateKey privateKey) {
        try {
            Signature sig = Signature.getInstance(ALG, CryptoConfig.BC);
            sig.initSign(privateKey);
            sig.update(data);
            return sig.sign();
        } catch (Exception e) {
            throw new CryptoException("ECDSA potpisivanje nije uspjelo", e);
        }
    }

    public boolean verify(byte[] data, byte[] signature, PublicKey publicKey) {
        try {
            Signature sig = Signature.getInstance(ALG, CryptoConfig.BC);
            sig.initVerify(publicKey);
            sig.update(data);
            return sig.verify(signature);
        } catch (Exception e) {
            throw new CryptoException("ECDSA verifikacija nije uspjela", e);
        }
    }
}
