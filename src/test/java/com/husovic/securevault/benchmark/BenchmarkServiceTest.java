package com.husovic.securevault.benchmark;

import com.husovic.securevault.benchmark.dto.AsymmetricBenchmarkResponse;
import com.husovic.securevault.benchmark.dto.SymmetricBenchmarkResponse;
import com.husovic.securevault.crypto.asymmetric.DiffieHellmanService;
import com.husovic.securevault.crypto.asymmetric.EcdhService;
import com.husovic.securevault.crypto.asymmetric.RsaService;
import com.husovic.securevault.crypto.symmetric.AesGcmService;
import com.husovic.securevault.crypto.symmetric.DesService;
import com.husovic.securevault.crypto.symmetric.SymmetricCipherService;
import com.husovic.securevault.crypto.symmetric.TripleDesService;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class BenchmarkServiceTest {

    private final BenchmarkStore store = new BenchmarkStore();
    private final BenchmarkService service = new BenchmarkService(
            List.<SymmetricCipherService>of(new AesGcmService(), new DesService(), new TripleDesService()),
            new RsaService(), new DiffieHellmanService(), new EcdhService(), store);

    @Test
    void symmetricProducesPositiveThroughputAndRows() {
        SymmetricBenchmarkResponse r = service.runSymmetric("AES", 256, 64, 3, 1);
        assertTrue(r.avgEncryptMs() >= 0);
        assertTrue(r.encryptThroughputMBs() > 0, "propusnost mora biti pozitivna");
        assertEquals(2, store.all().size(), "ENCRYPT + DECRYPT red");
    }

    @Test
    void rsaBenchmarkFillsEncDec() {
        AsymmetricBenchmarkResponse r = service.runAsymmetric("RSA", "2048", 2, 1);
        assertTrue(r.avgKeyGenMs() > 0);
        assertNotNull(r.avgEncryptMs());
        assertNotNull(r.avgDecryptMs());
        assertNull(r.avgExchangeMs());
    }

    @Test
    void ecdhBenchmarkFillsExchange() {
        AsymmetricBenchmarkResponse r = service.runAsymmetric("ECDH", "P-256", 2, 1);
        assertEquals("P-256", r.parameter());
        assertTrue(r.avgKeyGenMs() > 0);
        assertNotNull(r.avgExchangeMs());
        assertNull(r.avgEncryptMs());
    }

    @Test
    void unknownAlgorithmRejected() {
        assertThrows(RuntimeException.class, () -> service.runSymmetric("BLOWFISH", 128, 1, 1, 1));
    }
}
