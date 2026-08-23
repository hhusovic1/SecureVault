package com.husovic.securevault.vault;

import com.husovic.securevault.crypto.symmetric.AesGcmService;
import com.husovic.securevault.crypto.symmetric.CipherResult;
import com.husovic.securevault.session.SessionService;
import jakarta.annotation.PostConstruct;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import javax.crypto.SecretKey;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.List;
import java.util.UUID;

/**
 * Enkriptovana pohrana fajlova. Sadržaj se AES-256-GCM ključem sesije enkriptuje
 * <i>prije</i> upisa na disk, a dekriptuje tek pri preuzimanju. Fajl je vezan za
 * sesiju u kojoj je otpremljen — druga sesija mu ne može pristupiti.
 */
@Service
public class VaultService {

    private final AesGcmService aesGcmService;
    private final SessionService sessionService;
    private final FileMetadataRepository metadataRepository;
    private final Path storageDir;

    public VaultService(AesGcmService aesGcmService, SessionService sessionService,
                        FileMetadataRepository metadataRepository,
                        @Value("${securevault.storage-dir:vault-storage}") String storageDir) {
        this.aesGcmService = aesGcmService;
        this.sessionService = sessionService;
        this.metadataRepository = metadataRepository;
        this.storageDir = Path.of(storageDir);
    }

    @PostConstruct
    void ensureStorage() throws IOException {
        Files.createDirectories(storageDir);
    }

    public FileMetadata upload(String sessionId, String originalName, String contentType, byte[] content) {
        SecretKey key = aesGcmService.keyFromBytes(sessionService.requireEstablishedKey(sessionId));
        CipherResult encrypted = aesGcmService.encrypt(content, key);

        String fileId = UUID.randomUUID().toString();
        try {
            Files.write(pathFor(fileId), encrypted.ciphertext());
        } catch (IOException e) {
            throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, "Ne mogu upisati šifrat na disk");
        }

        FileMetadata meta = new FileMetadata(fileId, sessionId,
                originalName == null ? "file" : originalName,
                contentType == null ? "application/octet-stream" : contentType,
                content.length, encrypted.ivBase64(), Instant.now());
        return metadataRepository.save(meta);
    }

    public DecryptedFile download(String sessionId, String fileId) {
        SecretKey key = aesGcmService.keyFromBytes(sessionService.requireEstablishedKey(sessionId));
        FileMetadata meta = metadataRepository.findById(fileId)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Fajl ne postoji"));
        if (!meta.getSessionId().equals(sessionId)) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "Fajl ne pripada ovoj sesiji");
        }

        byte[] ciphertext;
        try {
            ciphertext = Files.readAllBytes(pathFor(fileId));
        } catch (IOException e) {
            throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, "Ne mogu pročitati šifrat sa diska");
        }
        CipherResult stored = CipherResult.fromBase64(meta.getIvBase64(),
                java.util.Base64.getEncoder().encodeToString(ciphertext));
        byte[] plaintext = aesGcmService.decrypt(stored, key);
        return new DecryptedFile(meta, plaintext);
    }

    public List<FileMetadata> list(String sessionId) {
        sessionService.requireEstablishedKey(sessionId); // autorizacija: mora biti uspostavljena
        return metadataRepository.findBySessionId(sessionId);
    }

    private Path pathFor(String fileId) {
        return storageDir.resolve(fileId + ".enc");
    }

    /** Dekriptovani fajl spreman za slanje klijentu. */
    public record DecryptedFile(FileMetadata metadata, byte[] content) {
    }
}
