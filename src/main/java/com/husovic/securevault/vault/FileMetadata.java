package com.husovic.securevault.vault;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

import java.time.Instant;

/**
 * Metapodaci pohranjenog fajla. Sam šifrat se čuva na disku (ne u bazi); ovdje su
 * samo referenca ({@code fileId}), IV/nonce potreban za dekripciju i osnovni podaci.
 * Enkriptovani sadržaj nikada nije u plaintextu ni na disku ni u bazi.
 */
@Entity
@Table(name = "vault_files")
public class FileMetadata {

    @Id
    @Column(length = 36)
    private String fileId;

    private String sessionId;
    private String originalName;
    private String contentType;
    private long plaintextSize;

    @Column(length = 32)
    private String ivBase64;

    private Instant createdAt;

    protected FileMetadata() {
    }

    public FileMetadata(String fileId, String sessionId, String originalName, String contentType,
                        long plaintextSize, String ivBase64, Instant createdAt) {
        this.fileId = fileId;
        this.sessionId = sessionId;
        this.originalName = originalName;
        this.contentType = contentType;
        this.plaintextSize = plaintextSize;
        this.ivBase64 = ivBase64;
        this.createdAt = createdAt;
    }

    public String getFileId() { return fileId; }
    public String getSessionId() { return sessionId; }
    public String getOriginalName() { return originalName; }
    public String getContentType() { return contentType; }
    public long getPlaintextSize() { return plaintextSize; }
    public String getIvBase64() { return ivBase64; }
    public Instant getCreatedAt() { return createdAt; }
}
