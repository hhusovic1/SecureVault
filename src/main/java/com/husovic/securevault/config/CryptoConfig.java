package com.husovic.securevault.config;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.context.annotation.Configuration;

import jakarta.annotation.PostConstruct;
import java.security.Security;

/**
 * Registruje Bouncy Castle kao JCE provider pri pokretanju aplikacije.
 * Bouncy Castle nam treba za RSA-OAEP, RSA-PSS, X25519/ECDH i HKDF.
 */
@Configuration
public class CryptoConfig {

    public static final String BC = BouncyCastleProvider.PROVIDER_NAME;

    @PostConstruct
    public void registerBouncyCastle() {
        if (Security.getProvider(BC) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    /** Idempotentna registracija za korištenje iz testova / statičkog konteksta. */
    public static void ensureProvider() {
        if (Security.getProvider(BC) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }
}
