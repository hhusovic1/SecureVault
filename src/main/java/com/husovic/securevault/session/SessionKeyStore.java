package com.husovic.securevault.session;

import org.springframework.stereotype.Component;

import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * In-memory skladište izvedenih AES ključeva sesija. Ključevi sesije NIKADA ne
 * napuštaju memoriju procesa — čim se sesija zatvori ili istekne, uklanjaju se odavde.
 * Ovim se garantuje da baza nikad ne sadrži tajni materijal.
 */
@Component
public class SessionKeyStore {

    private final ConcurrentHashMap<String, byte[]> keys = new ConcurrentHashMap<>();

    public void put(String sessionId, byte[] aesKey) {
        keys.put(sessionId, aesKey.clone());
    }

    public Optional<byte[]> get(String sessionId) {
        byte[] k = keys.get(sessionId);
        return k == null ? Optional.empty() : Optional.of(k.clone());
    }

    public boolean contains(String sessionId) {
        return keys.containsKey(sessionId);
    }

    public void remove(String sessionId) {
        byte[] k = keys.remove(sessionId);
        if (k != null) {
            java.util.Arrays.fill(k, (byte) 0); // best-effort brisanje tajne iz memorije
        }
    }
}
