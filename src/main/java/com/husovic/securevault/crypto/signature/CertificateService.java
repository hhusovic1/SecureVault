package com.husovic.securevault.crypto.signature;

import com.husovic.securevault.crypto.asymmetric.RsaService;
import org.springframework.stereotype.Service;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;

/**
 * Izdaje i verifikuje {@link SimpleCertificate} objekte koristeći RSA-PSS potpise.
 * Server koristi ovo da potpiše svoj dugoročni identitetski javni ključ i tako
 * omogući klijentu autentifikaciju servera tokom handshake-a.
 */
@Service
public class CertificateService {

    private final RsaSignatureService rsaSignatureService;
    private final RsaService rsaService;

    public CertificateService(RsaSignatureService rsaSignatureService, RsaService rsaService) {
        this.rsaSignatureService = rsaSignatureService;
        this.rsaService = rsaService;
    }

    /** Izdaje certifikat: {@code issuerPrivateKey} potpisuje vezu subjekt↔javni ključ. */
    public SimpleCertificate issue(String subject, PublicKey subjectPublicKey,
                                   String issuer, PrivateKey issuerPrivateKey) {
        String algorithm = subjectPublicKey.getAlgorithm();
        String pubB64 = rsaService.encodePublicKey(subjectPublicKey);
        byte[] tbs = SimpleCertificate.tbsBytes(subject, algorithm, pubB64, issuer);
        byte[] signature = rsaSignatureService.sign(tbs, issuerPrivateKey);
        return new SimpleCertificate(subject, algorithm, pubB64, issuer,
                Base64.getEncoder().encodeToString(signature));
    }

    /** Verifikuje potpis certifikata javnim ključem izdavaoca. */
    public boolean verify(SimpleCertificate cert, PublicKey issuerPublicKey) {
        byte[] signature = Base64.getDecoder().decode(cert.signatureBase64());
        return rsaSignatureService.verify(cert.tbsBytes(), signature, issuerPublicKey);
    }
}
