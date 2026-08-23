package com.husovic.securevault.session;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.Id;
import jakarta.persistence.Lob;
import jakarta.persistence.Table;

import java.time.Instant;

/**
 * Metapodaci sigurne sesije. NAMJERNO ne sadrži izvedeni AES ključ niti privatne
 * ključeve — oni žive isključivo u memoriji ({@link SessionKeyStore}). U bazi su
 * samo javni parametri i status, radi revizije i TTL-a.
 */
@Entity
@Table(name = "sessions")
public class Session {

    public enum Status { INITIALIZED, ESTABLISHED, EXPIRED, CLOSED }

    @Id
    @Column(length = 36)
    private String sessionId;

    @Enumerated(EnumType.STRING)
    private Status status;

    private String curve;

    @Lob
    @Column(length = 4096)
    private String clientEcdhPublicKey;

    @Lob
    @Column(length = 4096)
    private String serverEcdhPublicKey;

    private Instant createdAt;
    private Instant expiresAt;

    protected Session() {
    }

    public Session(String sessionId, String curve, String clientEcdhPublicKey,
                   String serverEcdhPublicKey, Instant createdAt, Instant expiresAt) {
        this.sessionId = sessionId;
        this.curve = curve;
        this.clientEcdhPublicKey = clientEcdhPublicKey;
        this.serverEcdhPublicKey = serverEcdhPublicKey;
        this.createdAt = createdAt;
        this.expiresAt = expiresAt;
        this.status = Status.INITIALIZED;
    }

    public boolean isExpired(Instant now) {
        return now.isAfter(expiresAt);
    }

    public String getSessionId() { return sessionId; }
    public Status getStatus() { return status; }
    public void setStatus(Status status) { this.status = status; }
    public String getCurve() { return curve; }
    public String getClientEcdhPublicKey() { return clientEcdhPublicKey; }
    public String getServerEcdhPublicKey() { return serverEcdhPublicKey; }
    public Instant getCreatedAt() { return createdAt; }
    public Instant getExpiresAt() { return expiresAt; }
}
