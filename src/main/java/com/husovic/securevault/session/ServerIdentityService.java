package com.husovic.securevault.session;

import com.husovic.securevault.crypto.asymmetric.RsaService;
import com.husovic.securevault.crypto.signature.CertificateService;
import com.husovic.securevault.crypto.signature.RsaSignatureService;
import com.husovic.securevault.crypto.signature.SimpleCertificate;
import jakarta.annotation.PostConstruct;
import org.springframework.stereotype.Service;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;

/**
 * Drži dugoročni ("identitetski") RSA par ključeva servera i njegov samostalno-potpisani
 * certifikat. Ovim ključem server potpisuje svoje efemerne ECDH parametre tokom handshake-a,
 * čime se klijentu omogućava autentifikacija servera.
 *
 * <p>Par se generiše u memoriji pri pokretanju — nikada se ne perzistira niti hardkodira,
 * u skladu sa sigurnosnim zahtjevom projekta.</p>
 */
@Service
public class ServerIdentityService {

    public static final String SERVER_NAME = "SecureVault Server";

    private final RsaService rsaService;
    private final CertificateService certificateService;

    private KeyPair identityKeyPair;
    private SimpleCertificate certificate;

    public ServerIdentityService(RsaService rsaService,
                                 CertificateService certificateService,
                                 RsaSignatureService rsaSignatureService) {
        this.rsaService = rsaService;
        this.certificateService = certificateService;
    }

    @PostConstruct
    void initIdentity() {
        this.identityKeyPair = rsaService.generateKeyPair(2048);
        // Samostalno-potpisan: subjekt i izdavalac su isti server.
        this.certificate = certificateService.issue(
                SERVER_NAME, identityKeyPair.getPublic(), SERVER_NAME, identityKeyPair.getPrivate());
    }

    public PrivateKey identityPrivateKey() {
        return identityKeyPair.getPrivate();
    }

    public PublicKey identityPublicKey() {
        return identityKeyPair.getPublic();
    }

    public SimpleCertificate certificate() {
        return certificate;
    }

    /** Certifikat javnog identitetskog ključa u Base64 (klijent ga koristi za verifikaciju). */
    public String identityPublicKeyBase64() {
        return rsaService.encodePublicKey(identityKeyPair.getPublic());
    }
}
