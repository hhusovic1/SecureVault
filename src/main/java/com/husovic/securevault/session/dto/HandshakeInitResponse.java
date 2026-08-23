package com.husovic.securevault.session.dto;

import com.husovic.securevault.crypto.signature.SimpleCertificate;

import java.time.Instant;

/**
 * Odgovor servera na init: efemerni ECDH javni ključ servera, potpis transkripta
 * (dugoročnim identitetskim ključem) i certifikat kojim klijent verifikuje potpis.
 *
 * @param transcript      tačan string koji je potpisan (klijent ga rekonstruiše i provjerava)
 * @param signatureBase64 RSA-PSS potpis nad {@code transcript}
 * @param hkdfInfo        "info" parametar za HKDF (klijent koristi isti pri izvođenju ključa)
 */
public record HandshakeInitResponse(
        String sessionId,
        String curve,
        String serverEcdhPublicKey,
        String transcript,
        String signatureBase64,
        SimpleCertificate certificate,
        String hkdfInfo,
        Instant expiresAt) {
}
