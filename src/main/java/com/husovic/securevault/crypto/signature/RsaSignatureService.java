package com.husovic.securevault.crypto.signature;

import com.husovic.securevault.config.CryptoConfig;
import com.husovic.securevault.crypto.CryptoException;
import org.springframework.stereotype.Service;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;

/**
 * RSA digitalni potpisi u PSS šemi (SHA-256, MGF1). PSS je randomizovana i
 * dokazivo sigurnija od determinističkog PKCS#1 v1.5 potpisivanja (poglavlje 3.6).
 */
@Service
public class RsaSignatureService {

    private static final String ALG = "SHA256withRSAandMGF1"; // RSASSA-PSS u BC

    static {
        CryptoConfig.ensureProvider();
    }

    public byte[] sign(byte[] data, PrivateKey privateKey) {
        try {
            Signature sig = Signature.getInstance(ALG, CryptoConfig.BC);
            sig.initSign(privateKey);
            sig.update(data);
            return sig.sign();
        } catch (Exception e) {
            throw new CryptoException("RSA-PSS potpisivanje nije uspjelo", e);
        }
    }

    public boolean verify(byte[] data, byte[] signature, PublicKey publicKey) {
        try {
            Signature sig = Signature.getInstance(ALG, CryptoConfig.BC);
            sig.initVerify(publicKey);
            sig.update(data);
            return sig.verify(signature);
        } catch (Exception e) {
            throw new CryptoException("RSA-PSS verifikacija nije uspjela", e);
        }
    }
}
