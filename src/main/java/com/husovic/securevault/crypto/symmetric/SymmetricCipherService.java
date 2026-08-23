package com.husovic.securevault.crypto.symmetric;

import javax.crypto.SecretKey;

/**
 * Zajednički interfejs za sve simetrične algoritme (DES, 3DES, AES).
 * Benchmark modul iterira kroz implementacije uniformno, bez poznavanja detalja.
 */
public interface SymmetricCipherService {

    /** Ime algoritma za prikaz i benchmark izvještaje (npr. "AES", "DES", "3DES"). */
    String algorithm();

    /** Podržane dužine ključa u bitovima. */
    int[] supportedKeySizes();

    /** Generiše novi slučajni ključ tražene dužine. */
    SecretKey generateKey(int keySizeBits);

    /** Enkripcija sa svježe generisanim IV/nonce po pozivu. */
    CipherResult encrypt(byte[] plaintext, SecretKey key);

    /** Dekripcija; baca izuzetak ako ključ/IV ne odgovaraju (ili autentifikacija ne prođe). */
    byte[] decrypt(CipherResult ciphertext, SecretKey key);
}
