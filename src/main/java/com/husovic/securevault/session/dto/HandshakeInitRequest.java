package com.husovic.securevault.session.dto;

import jakarta.validation.constraints.NotBlank;

/**
 * Korak 1 handshake-a: klijent bira krivu i šalje svoj efemerni ECDH javni ključ.
 */
public record HandshakeInitRequest(
        @NotBlank String curve,
        @NotBlank String clientEcdhPublicKey) {
}
