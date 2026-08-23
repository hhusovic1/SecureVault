package com.husovic.securevault.session;

import com.husovic.securevault.crypto.asymmetric.EcdhService;
import com.husovic.securevault.crypto.asymmetric.RsaService;
import com.husovic.securevault.crypto.kdf.HkdfService;
import com.husovic.securevault.crypto.signature.CertificateService;
import com.husovic.securevault.crypto.signature.RsaSignatureService;
import com.husovic.securevault.crypto.signature.SimpleCertificate;
import com.husovic.securevault.crypto.symmetric.AesGcmService;
import com.husovic.securevault.crypto.symmetric.CipherResult;
import com.husovic.securevault.session.dto.HandshakeFinishRequest;
import com.husovic.securevault.session.dto.HandshakeFinishResponse;
import com.husovic.securevault.session.dto.HandshakeInitRequest;
import com.husovic.securevault.session.dto.HandshakeInitResponse;
import com.husovic.securevault.vault.FileMetadata;
import com.husovic.securevault.vault.VaultService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.web.server.ResponseStatusException;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.PublicKey;

import static org.junit.jupiter.api.Assertions.*;

/**
 * End-to-end test hibridne sesije: simulira klijenta koristeći iste kripto-servise,
 * i dokazuje da (1) klijent može autentifikovati server, (2) obje strane izvedu
 * identičan AES ključ, (3) fajl enkriptovan ključem sesije se ispravno vraća, i
 * (4) tuđa sesija ne može pristupiti fajlu.
 */
@SpringBootTest
class HandshakeVaultIntegrationTest {

    @Autowired SessionService sessionService;
    @Autowired ServerIdentityService serverIdentity;
    @Autowired EcdhService ecdh;
    @Autowired HkdfService hkdf;
    @Autowired AesGcmService aes;
    @Autowired RsaService rsa;
    @Autowired RsaSignatureService rsaSig;
    @Autowired CertificateService certService;
    @Autowired VaultService vaultService;

    @Test
    void fullHandshakeThenVaultRoundTrip() {
        String curve = EcdhService.CURVE_25519;

        // --- Klijent: dohvat i verifikacija certifikata servera ---
        SimpleCertificate cert = serverIdentity.certificate();
        PublicKey serverIdentityKey = rsa.decodePublicKey(cert.publicKeyBase64());
        assertTrue(certService.verify(cert, serverIdentityKey), "certifikat mora biti validan (self-signed)");

        // --- Klijent: efemerni ECDH par + init ---
        KeyPair clientEphemeral = ecdh.generateKeyPair(curve);
        String clientPub = ecdh.encodePublicKey(clientEphemeral.getPublic());
        HandshakeInitResponse init = sessionService.init(new HandshakeInitRequest(curve, clientPub));

        // --- Klijent: verifikacija potpisa transkripta identitetskim ključem servera ---
        String expectedTranscript = String.join("|", "SecureVault-HS-v1", init.sessionId(),
                curve, clientPub, init.serverEcdhPublicKey());
        assertEquals(expectedTranscript, init.transcript(), "klijent rekonstruiše isti transkript");
        byte[] sig = java.util.Base64.getDecoder().decode(init.signatureBase64());
        assertTrue(rsaSig.verify(expectedTranscript.getBytes(StandardCharsets.UTF_8), sig, serverIdentityKey),
                "potpis servera mora biti validan");

        // --- Klijent: izvođenje istog AES ključa ---
        PublicKey serverPub = ecdh.decodePublicKey(curve, init.serverEcdhPublicKey());
        byte[] shared = ecdh.computeSharedSecret(curve, clientEphemeral.getPrivate(), serverPub);
        byte[] clientAesKey = hkdf.deriveAes256Key(shared, null, init.hkdfInfo());

        // --- Klijent: Finished poruka -> finish ---
        String finished = SessionService.expectedFinished(init.sessionId());
        CipherResult confirmation = aes.encrypt(finished.getBytes(StandardCharsets.UTF_8),
                aes.keyFromBytes(clientAesKey));
        HandshakeFinishResponse finish = sessionService.finish(new HandshakeFinishRequest(
                init.sessionId(), confirmation.ivBase64(), confirmation.ciphertextBase64()));
        assertEquals("ESTABLISHED", finish.status());

        // --- Vault: upload + download round-trip ---
        byte[] content = "Povjerljiv sadržaj fajla u trezoru".getBytes(StandardCharsets.UTF_8);
        FileMetadata meta = vaultService.upload(init.sessionId(), "tajna.txt", "text/plain", content);
        VaultService.DecryptedFile back = vaultService.download(init.sessionId(), meta.getFileId());
        assertArrayEquals(content, back.content(), "fajl mora biti identičan nakon dekripcije");

        // --- Izolacija: druga (uspostavljena) sesija ne smije pristupiti tuđem fajlu ---
        String otherSession = establishSession(EcdhService.CURVE_P256);
        ResponseStatusException ex = assertThrows(ResponseStatusException.class,
                () -> vaultService.download(otherSession, meta.getFileId()));
        assertEquals(403, ex.getStatusCode().value());
    }

    @Test
    void finishFailsWithWrongKey() {
        String curve = EcdhService.CURVE_25519;
        KeyPair clientEphemeral = ecdh.generateKeyPair(curve);
        HandshakeInitResponse init = sessionService.init(
                new HandshakeInitRequest(curve, ecdh.encodePublicKey(clientEphemeral.getPublic())));

        // Klijent koji je izveo POGREŠAN ključ ne smije proći finish.
        byte[] wrongKey = new byte[32];
        CipherResult bad = aes.encrypt(SessionService.expectedFinished(init.sessionId())
                .getBytes(StandardCharsets.UTF_8), aes.keyFromBytes(wrongKey));
        ResponseStatusException ex = assertThrows(ResponseStatusException.class,
                () -> sessionService.finish(new HandshakeFinishRequest(
                        init.sessionId(), bad.ivBase64(), bad.ciphertextBase64())));
        assertEquals(400, ex.getStatusCode().value());
    }

    private String establishSession(String curve) {
        KeyPair client = ecdh.generateKeyPair(curve);
        HandshakeInitResponse init = sessionService.init(
                new HandshakeInitRequest(curve, ecdh.encodePublicKey(client.getPublic())));
        byte[] shared = ecdh.computeSharedSecret(curve, client.getPrivate(),
                ecdh.decodePublicKey(curve, init.serverEcdhPublicKey()));
        byte[] key = hkdf.deriveAes256Key(shared, null, init.hkdfInfo());
        CipherResult conf = aes.encrypt(SessionService.expectedFinished(init.sessionId())
                .getBytes(StandardCharsets.UTF_8), aes.keyFromBytes(key));
        sessionService.finish(new HandshakeFinishRequest(init.sessionId(),
                conf.ivBase64(), conf.ciphertextBase64()));
        return init.sessionId();
    }
}
