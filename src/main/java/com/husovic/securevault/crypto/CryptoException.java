package com.husovic.securevault.crypto;

/** Neprovjeravani wrapper oko JCE checked izuzetaka radi čistijeg servisnog API-ja. */
public class CryptoException extends RuntimeException {
    public CryptoException(String message, Throwable cause) {
        super(message, cause);
    }

    public CryptoException(String message) {
        super(message);
    }
}
