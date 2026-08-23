package com.husovic.securevault.benchmark.dto;

/**
 * Rezultat asimetričnog benchmarka. {@code avgEncryptMs}/{@code avgDecryptMs} su
 * popunjeni za RSA, a {@code avgExchangeMs} za DH/ECDH (vrijeme cijele razmjene).
 */
public record AsymmetricBenchmarkResponse(
        String algorithm,
        String parameter,
        int repetitions,
        double avgKeyGenMs,
        Double avgEncryptMs,
        Double avgDecryptMs,
        Double avgExchangeMs) {
}
