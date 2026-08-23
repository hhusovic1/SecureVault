package com.husovic.securevault.session;

import com.husovic.securevault.crypto.asymmetric.EcdhService;
import com.husovic.securevault.crypto.kdf.HkdfService;
import com.husovic.securevault.crypto.signature.RsaSignatureService;
import com.husovic.securevault.crypto.symmetric.AesGcmService;
import com.husovic.securevault.crypto.symmetric.CipherResult;
import com.husovic.securevault.session.dto.HandshakeFinishRequest;
import com.husovic.securevault.session.dto.HandshakeFinishResponse;
import com.husovic.securevault.session.dto.HandshakeInitRequest;
import com.husovic.securevault.session.dto.HandshakeInitResponse;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.PublicKey;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.UUID;

/**
 * Srce hibridnog kriptosistema — pojednostavljeni TLS-like handshake:
 *
 * <ol>
 *   <li><b>init</b>: klijent šalje efemerni ECDH javni ključ; server generiše svoj
 *       efemerni par, izračuna zajedničku tajnu, HKDF-om izvede AES-256 ključ i
 *       potpiše transkript svojim <i>dugoročnim</i> identitetskim ključem.</li>
 *   <li><b>finish</b>: klijent (nakon verifikacije potpisa) dokaže posjedovanje
 *       istog ključa AES-GCM "Finished" porukom; server je dekriptuje i uspostavi sesiju.</li>
 * </ol>
 *
 * <p>Efemerni ECDH par po sesiji daje <b>Perfect Forward Secrecy</b>: kompromitacija
 * dugoročnog ključa u budućnosti ne otkriva ranije snimljene sesije (poglavlje 3.5.2).</p>
 */
@Service
public class SessionService {

    private static final String PROTO = "SecureVault-HS-v1";
    private static final Duration TTL = Duration.ofMinutes(30);

    private final EcdhService ecdhService;
    private final HkdfService hkdfService;
    private final RsaSignatureService rsaSignatureService;
    private final AesGcmService aesGcmService;
    private final ServerIdentityService serverIdentity;
    private final SessionRepository sessionRepository;
    private final SessionKeyStore keyStore;

    public SessionService(EcdhService ecdhService, HkdfService hkdfService,
                          RsaSignatureService rsaSignatureService, AesGcmService aesGcmService,
                          ServerIdentityService serverIdentity, SessionRepository sessionRepository,
                          SessionKeyStore keyStore) {
        this.ecdhService = ecdhService;
        this.hkdfService = hkdfService;
        this.rsaSignatureService = rsaSignatureService;
        this.aesGcmService = aesGcmService;
        this.serverIdentity = serverIdentity;
        this.sessionRepository = sessionRepository;
        this.keyStore = keyStore;
    }

    @Transactional
    public HandshakeInitResponse init(HandshakeInitRequest request) {
        String curve = request.curve();
        PublicKey clientPub = ecdhService.decodePublicKey(curve, request.clientEcdhPublicKey());

        // Efemerni par servera — nov po svakoj sesiji (PFS).
        KeyPair serverEphemeral = ecdhService.generateKeyPair(curve);
        String serverPubB64 = ecdhService.encodePublicKey(serverEphemeral.getPublic());

        // Zajednička tajna -> HKDF -> AES-256 ključ sesije.
        String sessionId = UUID.randomUUID().toString();
        byte[] shared = ecdhService.computeSharedSecret(curve, serverEphemeral.getPrivate(), clientPub);
        String hkdfInfo = PROTO + "|" + sessionId;
        byte[] aesKey = hkdfService.deriveAes256Key(shared, null, hkdfInfo);
        keyStore.put(sessionId, aesKey);

        // Potpis transkripta dugoročnim identitetskim ključem -> autentifikacija servera.
        String transcript = transcript(sessionId, curve, request.clientEcdhPublicKey(), serverPubB64);
        byte[] signature = rsaSignatureService.sign(transcript.getBytes(StandardCharsets.UTF_8),
                serverIdentity.identityPrivateKey());

        Instant now = Instant.now();
        Session session = new Session(sessionId, curve, request.clientEcdhPublicKey(),
                serverPubB64, now, now.plus(TTL));
        sessionRepository.save(session);

        return new HandshakeInitResponse(sessionId, curve, serverPubB64, transcript,
                Base64.getEncoder().encodeToString(signature), serverIdentity.certificate(),
                hkdfInfo, session.getExpiresAt());
    }

    @Transactional
    public HandshakeFinishResponse finish(HandshakeFinishRequest request) {
        Session session = loadActive(request.sessionId());
        byte[] aesKey = keyStore.get(session.getSessionId())
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.GONE, "Ključ sesije više ne postoji"));
        SecretKey key = aesGcmService.keyFromBytes(aesKey);

        // Verifikuj "Finished" poruku: dokaz da je klijent izveo isti ključ.
        CipherResult confirmation = CipherResult.fromBase64(
                request.confirmationIv(), request.confirmationCiphertext());
        byte[] plaintext;
        try {
            plaintext = aesGcmService.decrypt(confirmation, key);
        } catch (RuntimeException e) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                    "Finished poruka se ne može dekriptovati — ključevi se ne poklapaju");
        }
        String expected = expectedFinished(session.getSessionId());
        if (!expected.equals(new String(plaintext, StandardCharsets.UTF_8))) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Neispravan sadržaj Finished poruke");
        }

        session.setStatus(Session.Status.ESTABLISHED);
        sessionRepository.save(session);
        return new HandshakeFinishResponse(session.getSessionId(), session.getStatus().name(),
                "Sesija uspostavljena — kanal je siguran (AES-256-GCM).");
    }

    /** Vraća AES ključ uspostavljene sesije ili baca odgovarajući HTTP izuzetak. */
    public byte[] requireEstablishedKey(String sessionId) {
        Session session = loadActive(sessionId);
        if (session.getStatus() != Session.Status.ESTABLISHED) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN,
                    "Sesija nije uspostavljena (status: " + session.getStatus() + ")");
        }
        return keyStore.get(sessionId)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.GONE, "Ključ sesije više ne postoji"));
    }

    public Session getSession(String sessionId) {
        return loadActive(sessionId);
    }

    /** String koji klijent treba enkriptovati kao "Finished" poruku. */
    public static String expectedFinished(String sessionId) {
        return "SecureVault client finished|" + sessionId;
    }

    private static String transcript(String sessionId, String curve, String clientPub, String serverPub) {
        return String.join("|", PROTO, sessionId, curve, clientPub, serverPub);
    }

    private Session loadActive(String sessionId) {
        Session session = sessionRepository.findById(sessionId)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Sesija ne postoji"));
        if (session.getStatus() == Session.Status.EXPIRED || session.isExpired(Instant.now())) {
            if (session.getStatus() != Session.Status.EXPIRED) {
                session.setStatus(Session.Status.EXPIRED);
                sessionRepository.save(session);
            }
            keyStore.remove(sessionId);
            throw new ResponseStatusException(HttpStatus.GONE, "Sesija je istekla");
        }
        return session;
    }
}
