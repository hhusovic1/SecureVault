package com.husovic.securevault.vuln;

import com.husovic.securevault.crypto.symmetric.ManualDes;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;

/**
 * EDUKATIVNA DEMONSTRACIJA — brute-force napad na DES sa <b>vještački skraćenim</b>
 * prostorom ključeva (npr. 20–28 bita umjesto punih 56). Poznat je par
 * (otvoreni tekst, šifrat); napadač redom isprobava sve moguće ključeve dok ne
 * pronađe onaj koji reprodukuje šifrat.
 *
 * <p>Cilj je pokazati kako vrijeme probijanja raste <i>eksponencijalno</i> sa
 * dužinom ključa (≈ 2<sup>n</sup>), čime se empirijski potkrepljuje teorijska
 * tvrdnja da je puni 56-bitni DES danas nesiguran. Ovo NIJE upotrebljiv alat za
 * napad na tuđe sisteme — radi isključivo nad ključem koji sami generišemo u
 * kontrolisanom okruženju.</p>
 *
 * <p><b>Napomena o paritetu:</b> DES ignoriše 8 paritetnih bitova ključa (PC-1 ih
 * odbacuje), pa napad može pronaći ekvivalentan ključ koji se od tajnog razlikuje
 * samo u paritetnom bitu — oba daju isti šifrat. Ovo je poznato svojstvo DES-a.</p>
 */
@Service
public class DesBruteForceService {

    /** Fiksni poznati blok otvorenog teksta (napadaču poznat). */
    public static final long KNOWN_PLAINTEXT = 0x0123456789ABCDEFL;
    private static final int MAX_BITS = 30; // sigurnosna granica da demo ne traje predugo

    private final SecureRandom random = new SecureRandom();

    /**
     * @param keyBits broj nepoznatih bitova ključa (efektivna veličina prostora = 2^keyBits)
     */
    public BruteForceResult run(int keyBits) {
        if (keyBits < 1 || keyBits > MAX_BITS) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                    "keyBits mora biti u opsegu 1.." + MAX_BITS + " (edukativna granica)");
        }
        long keyspace = 1L << keyBits;
        long secretKey = Math.floorMod(random.nextLong(), keyspace);
        long target = ManualDes.encryptBlock(KNOWN_PLAINTEXT, secretKey);

        long start = System.nanoTime();
        long attempts = 0;
        long foundKey = -1;
        boolean found = false;
        for (long candidate = 0; candidate < keyspace; candidate++) {
            attempts++;
            if (ManualDes.encryptBlock(KNOWN_PLAINTEXT, candidate) == target) {
                foundKey = candidate;
                found = true;
                break;
            }
        }
        double elapsedMs = (System.nanoTime() - start) / 1_000_000.0;
        double keysPerSecond = elapsedMs > 0 ? attempts / (elapsedMs / 1000.0) : 0;

        return new BruteForceResult(keyBits, keyspace, attempts, secretKey, foundKey, found,
                elapsedMs, keysPerSecond);
    }

    /**
     * Pokreće brute-force za opseg dužina ključa — daje niz tačaka za graf
     * (vrijeme vs. broj bitova) koji vizuelno pokazuje eksponencijalni rast.
     */
    public List<BruteForceResult> scaling(int minBits, int maxBits) {
        if (minBits < 1 || maxBits > MAX_BITS || minBits > maxBits) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                    "Neispravan opseg (dozvoljeno 1.." + MAX_BITS + ", minBits <= maxBits)");
        }
        List<BruteForceResult> results = new ArrayList<>();
        for (int bits = minBits; bits <= maxBits; bits++) {
            results.add(run(bits));
        }
        return results;
    }

    /**
     * @param keyBits        broj nepoznatih bitova
     * @param keyspace       veličina prostora ključeva (2^keyBits)
     * @param attempts       broj isprobanih ključeva do pronalaska
     * @param secretKey      tajni ključ (otkriven radi verifikacije demonstracije)
     * @param foundKey       ključ koji je napad pronašao
     * @param found          da li je ključ pronađen
     * @param elapsedMs      utrošeno vrijeme (ms)
     * @param keysPerSecond  brzina pretrage (ključeva/s) — mjera snage hardvera
     */
    public record BruteForceResult(
            int keyBits,
            long keyspace,
            long attempts,
            long secretKey,
            long foundKey,
            boolean found,
            double elapsedMs,
            double keysPerSecond) {
    }
}
