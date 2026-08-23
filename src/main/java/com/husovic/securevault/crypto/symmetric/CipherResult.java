package com.husovic.securevault.crypto.symmetric;

import java.util.Base64;

/**
 * Rezultat simetrične enkripcije: inicijalizacijski vektor (IV/nonce) + šifrat.
 * Kod AES-GCM je autentifikacijski tag zalijepljen na kraj {@code ciphertext} od strane JCE.
 */
public record CipherResult(byte[] iv, byte[] ciphertext) {

    public String ivBase64() {
        return Base64.getEncoder().encodeToString(iv);
    }

    public String ciphertextBase64() {
        return Base64.getEncoder().encodeToString(ciphertext);
    }

    public static CipherResult fromBase64(String ivB64, String ctB64) {
        return new CipherResult(
                Base64.getDecoder().decode(ivB64),
                Base64.getDecoder().decode(ctB64));
    }
}
