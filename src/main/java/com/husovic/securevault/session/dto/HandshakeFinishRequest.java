package com.husovic.securevault.session.dto;

import jakarta.validation.constraints.NotBlank;

/**
 * Korak 2 handshake-a. Klijent je verifikovao potpis servera i izveo isti AES ključ.
 * Kao dokaz posjedovanja ključa ("Finished" poruka, analogno TLS-u) klijent šalje
 * AES-GCM enkriptovan poznati string; server ga dekriptuje i potvrđuje poklapanje ključeva.
 */
public record HandshakeFinishRequest(
        @NotBlank String sessionId,
        @NotBlank String confirmationIv,
        @NotBlank String confirmationCiphertext) {
}
