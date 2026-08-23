package com.husovic.securevault.benchmark;

import java.time.Instant;

/**
 * Normalizovan red rezultata — jedna izmjerena operacija. Ovakav "dugi" oblik je
 * idealan za CSV izvoz i naknadno crtanje grafova (npr. matplotlib).
 *
 * @param category      SYMMETRIC | ASYMMETRIC
 * @param algorithm     AES | DES | 3DES | RSA | DH | ECDH
 * @param parameter     dužina ključa u bitovima ili naziv krive (npr. "256", "P-256")
 * @param dataSizeKB    veličina podataka u KB (null za asimetrične keygen/exchange)
 * @param repetitions   broj mjerenih ponavljanja (nakon warm-up-a)
 * @param operation     ENCRYPT | DECRYPT | KEYGEN | EXCHANGE
 * @param avgMs         prosječno vrijeme po operaciji (ms)
 * @param throughputMBs propusnost (MB/s) — null gdje nema smisla (asimetrični)
 */
public record BenchmarkRow(
        String category,
        String algorithm,
        String parameter,
        Integer dataSizeKB,
        int repetitions,
        String operation,
        double avgMs,
        Double throughputMBs,
        Instant timestamp) {
}
