package com.husovic.securevault.benchmark;

import com.husovic.securevault.benchmark.dto.AsymmetricBenchmarkResponse;
import com.husovic.securevault.benchmark.dto.SymmetricBenchmarkResponse;
import com.husovic.securevault.crypto.asymmetric.DiffieHellmanService;
import com.husovic.securevault.crypto.asymmetric.EcdhService;
import com.husovic.securevault.crypto.asymmetric.RsaService;
import com.husovic.securevault.crypto.symmetric.CipherResult;
import com.husovic.securevault.crypto.symmetric.SymmetricCipherService;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import javax.crypto.SecretKey;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * Empirijsko mjerenje performansi algoritama. Ključno za tačnost je zagrijavanje
 * JVM-a (warm-up) prije mjerenja — bez toga JIT kompajlacija i lijena inicijalizacija
 * iskrivljuju prve iteracije. Rezultati se normalizuju u {@link BenchmarkRow} i
 * akumuliraju u {@link BenchmarkStore} za kasniji CSV/JSON izvoz.
 */
@Service
public class BenchmarkService {

    private static final double MB = 1024.0 * 1024.0;
    private final SecureRandom random = new SecureRandom();

    private final Map<String, SymmetricCipherService> symmetric = new LinkedHashMap<>();
    private final RsaService rsaService;
    private final DiffieHellmanService dhService;
    private final EcdhService ecdhService;
    private final BenchmarkStore store;

    public BenchmarkService(List<SymmetricCipherService> symmetricServices, RsaService rsaService,
                            DiffieHellmanService dhService, EcdhService ecdhService, BenchmarkStore store) {
        for (SymmetricCipherService s : symmetricServices) {
            symmetric.put(s.algorithm().toUpperCase(Locale.ROOT), s);
        }
        this.rsaService = rsaService;
        this.dhService = dhService;
        this.ecdhService = ecdhService;
        this.store = store;
    }

    // ---------------- Simetrični ----------------

    public SymmetricBenchmarkResponse runSymmetric(String algorithm, int keySize, int dataSizeKB,
                                                   int repetitions, int warmup) {
        SymmetricCipherService svc = symmetric.get(algorithm.toUpperCase(Locale.ROOT));
        if (svc == null) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                    "Nepoznat simetrični algoritam: " + algorithm + " (dostupno: " + symmetric.keySet() + ")");
        }
        int effectiveKeySize = "AES".equalsIgnoreCase(algorithm) ? keySize : svc.supportedKeySizes()[0];
        SecretKey key = svc.generateKey(effectiveKeySize);

        byte[] data = new byte[dataSizeKB * 1024];
        random.nextBytes(data);

        double encMs = measureAvgMs(warmup, repetitions, () -> svc.encrypt(data, key));
        CipherResult ct = svc.encrypt(data, key);
        double decMs = measureAvgMs(warmup, repetitions, () -> svc.decrypt(ct, key));

        double encThroughput = throughputMBs(data.length, encMs);
        double decThroughput = throughputMBs(data.length, decMs);

        Instant now = Instant.now();
        String param = String.valueOf(effectiveKeySize);
        store.addAll(List.of(
                new BenchmarkRow("SYMMETRIC", svc.algorithm(), param, dataSizeKB, repetitions,
                        "ENCRYPT", encMs, encThroughput, now),
                new BenchmarkRow("SYMMETRIC", svc.algorithm(), param, dataSizeKB, repetitions,
                        "DECRYPT", decMs, decThroughput, now)));

        return new SymmetricBenchmarkResponse(svc.algorithm(), effectiveKeySize, dataSizeKB, repetitions,
                encMs, decMs, encThroughput, decThroughput);
    }

    // ---------------- Asimetrični ----------------

    public AsymmetricBenchmarkResponse runAsymmetric(String algorithm, String parameter,
                                                     int repetitions, int warmup) {
        String alg = algorithm.toUpperCase(Locale.ROOT);
        return switch (alg) {
            case "RSA" -> benchmarkRsa(parameter, repetitions, warmup);
            case "DH" -> benchmarkDh(parameter, repetitions, warmup);
            case "ECDH" -> benchmarkEcdh(parameter, repetitions, warmup);
            default -> throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                    "Nepoznat asimetrični algoritam: " + algorithm + " (dostupno: RSA, DH, ECDH)");
        };
    }

    private AsymmetricBenchmarkResponse benchmarkRsa(String parameter, int reps, int warmup) {
        int bits = parseInt(parameter, "RSA dužina ključa");
        double keyGenMs = measureAvgMs(warmup, reps, () -> rsaService.generateKeyPair(bits));

        KeyPair kp = rsaService.generateKeyPair(bits);
        byte[] msg = new byte[32];
        random.nextBytes(msg);
        double encMs = measureAvgMs(warmup, reps, () -> rsaService.encrypt(msg, kp.getPublic()));
        byte[] ct = rsaService.encrypt(msg, kp.getPublic());
        double decMs = measureAvgMs(warmup, reps, () -> rsaService.decrypt(ct, kp.getPrivate()));

        pushAsymmetric("RSA", parameter, reps, keyGenMs, encMs, decMs, null);
        return new AsymmetricBenchmarkResponse("RSA", parameter, reps, keyGenMs, encMs, decMs, null);
    }

    private AsymmetricBenchmarkResponse benchmarkDh(String parameter, int reps, int warmup) {
        int bits = parseInt(parameter, "DH grupa");
        double keyGenMs = measureAvgMs(warmup, reps, () -> dhService.generateKeyPair(bits));
        double exchangeMs = measureAvgMs(warmup, reps, () -> {
            KeyPair a = dhService.generateKeyPair(bits);
            KeyPair b = dhService.generateKeyPair(bits);
            dhService.computeSharedSecret(a.getPrivate(), b.getPublic());
            dhService.computeSharedSecret(b.getPrivate(), a.getPublic());
        });
        pushAsymmetric("DH", parameter, reps, keyGenMs, null, null, exchangeMs);
        return new AsymmetricBenchmarkResponse("DH", parameter, reps, keyGenMs, null, null, exchangeMs);
    }

    private AsymmetricBenchmarkResponse benchmarkEcdh(String parameter, int reps, int warmup) {
        String curve = normalizeCurve(parameter);
        double keyGenMs = measureAvgMs(warmup, reps, () -> ecdhService.generateKeyPair(curve));
        double exchangeMs = measureAvgMs(warmup, reps, () -> {
            KeyPair a = ecdhService.generateKeyPair(curve);
            KeyPair b = ecdhService.generateKeyPair(curve);
            ecdhService.computeSharedSecret(curve, a.getPrivate(), b.getPublic());
            ecdhService.computeSharedSecret(curve, b.getPrivate(), a.getPublic());
        });
        pushAsymmetric("ECDH", curve, reps, keyGenMs, null, null, exchangeMs);
        return new AsymmetricBenchmarkResponse("ECDH", curve, reps, keyGenMs, null, null, exchangeMs);
    }

    private void pushAsymmetric(String alg, String param, int reps, double keyGenMs,
                                Double encMs, Double decMs, Double exchangeMs) {
        Instant now = Instant.now();
        List<BenchmarkRow> rows = new ArrayList<>();
        rows.add(new BenchmarkRow("ASYMMETRIC", alg, param, null, reps, "KEYGEN", keyGenMs, null, now));
        if (encMs != null) {
            rows.add(new BenchmarkRow("ASYMMETRIC", alg, param, null, reps, "ENCRYPT", encMs, null, now));
        }
        if (decMs != null) {
            rows.add(new BenchmarkRow("ASYMMETRIC", alg, param, null, reps, "DECRYPT", decMs, null, now));
        }
        if (exchangeMs != null) {
            rows.add(new BenchmarkRow("ASYMMETRIC", alg, param, null, reps, "EXCHANGE", exchangeMs, null, now));
        }
        store.addAll(rows);
    }

    // ---------------- Pomoćne ----------------

    private double measureAvgMs(int warmup, int reps, Runnable op) {
        if (reps <= 0) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "repetitions mora biti > 0");
        }
        for (int i = 0; i < warmup; i++) {
            op.run();
        }
        long start = System.nanoTime();
        for (int i = 0; i < reps; i++) {
            op.run();
        }
        long elapsedNs = System.nanoTime() - start;
        return (elapsedNs / 1_000_000.0) / reps;
    }

    private double throughputMBs(long bytes, double avgMs) {
        if (avgMs <= 0) {
            return 0;
        }
        double bytesPerSec = bytes / (avgMs / 1000.0);
        return bytesPerSec / MB;
    }

    private int parseInt(String value, String what) {
        try {
            return Integer.parseInt(value.trim());
        } catch (NumberFormatException e) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Neispravan parametar (" + what + "): " + value);
        }
    }

    private String normalizeCurve(String parameter) {
        String p = parameter.trim().toUpperCase(Locale.ROOT).replace("-", "");
        return switch (p) {
            case "X25519", "CURVE25519", "25519" -> EcdhService.CURVE_25519;
            case "P256", "SECP256R1", "NISTP256", "256" -> EcdhService.CURVE_P256;
            default -> throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                    "Nepoznata kriva: " + parameter + " (dostupno: X25519/Curve25519, P-256)");
        };
    }
}
