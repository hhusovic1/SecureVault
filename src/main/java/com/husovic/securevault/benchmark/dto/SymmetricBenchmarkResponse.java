package com.husovic.securevault.benchmark.dto;

public record SymmetricBenchmarkResponse(
        String algorithm,
        int keySizeBits,
        int dataSizeKB,
        int repetitions,
        double avgEncryptMs,
        double avgDecryptMs,
        double encryptThroughputMBs,
        double decryptThroughputMBs) {
}
