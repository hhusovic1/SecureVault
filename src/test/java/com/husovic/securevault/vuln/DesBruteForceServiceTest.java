package com.husovic.securevault.vuln;

import com.husovic.securevault.crypto.symmetric.ManualDes;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class DesBruteForceServiceTest {

    private final DesBruteForceService service = new DesBruteForceService();

    @Test
    void findsKeyWithinSmallKeyspace() {
        DesBruteForceService.BruteForceResult r = service.run(12);
        assertTrue(r.found(), "ključ mora biti pronađen u prostoru 2^12");
        // Pronađeni ključ mora reprodukovati šifrat (može biti paritetno-ekvivalentan tajnom).
        assertEquals(
                ManualDes.encryptBlock(DesBruteForceService.KNOWN_PLAINTEXT, r.secretKey()),
                ManualDes.encryptBlock(DesBruteForceService.KNOWN_PLAINTEXT, r.foundKey()),
                "pronađeni ključ mora dati isti šifrat kao tajni");
        assertTrue(r.attempts() <= r.keyspace());
        assertEquals(1L << 12, r.keyspace());
    }

    @Test
    void scalingProducesMonotonicKeyspace() {
        var results = service.scaling(8, 12);
        assertEquals(5, results.size());
        for (int i = 1; i < results.size(); i++) {
            assertTrue(results.get(i).keyspace() > results.get(i - 1).keyspace(),
                    "prostor ključeva mora rasti sa brojem bitova");
        }
    }

    @Test
    void rejectsOutOfRangeBits() {
        assertThrows(RuntimeException.class, () -> service.run(40));
        assertThrows(RuntimeException.class, () -> service.run(0));
    }
}
