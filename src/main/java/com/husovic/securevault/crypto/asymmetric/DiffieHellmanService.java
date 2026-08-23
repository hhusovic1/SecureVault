package com.husovic.securevault.crypto.asymmetric;

import com.husovic.securevault.config.CryptoConfig;
import com.husovic.securevault.crypto.CryptoException;
import org.springframework.stereotype.Service;

import javax.crypto.KeyAgreement;
import javax.crypto.spec.DHParameterSpec;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

/**
 * Klasični Diffie-Hellman nad Z*p koristeći standardizovane MODP grupe iz
 * RFC 3526 (grupa 14 = 2048 bita, grupa 15 = 3072 bita, generator g = 2).
 * Služi kao "klasična" tačka poređenja naspram ECDH-a u benchmarku (Tabela 3.14).
 */
@Service
public class DiffieHellmanService {

    /** RFC 3526 grupa 14 — 2048-bitni MODP prosti broj. */
    private static final String P_2048 =
            "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
            + "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
            + "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
            + "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
            + "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
            + "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
            + "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
            + "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
            + "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
            + "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
            + "15728E5A8AACAA68FFFFFFFFFFFFFFFF";

    /** RFC 3526 grupa 15 — 3072-bitni MODP prosti broj. */
    private static final String P_3072 =
            "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
            + "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
            + "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
            + "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
            + "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
            + "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
            + "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
            + "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
            + "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
            + "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
            + "15728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64"
            + "ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7"
            + "ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6B"
            + "F12FFA06D98A0864D87602733EC86A64521F2B18177B200C"
            + "BBE117577A615D6C770988C0BAD946E208E24FA074E5AB31"
            + "43DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF";

    private static final BigInteger G = BigInteger.TWO;

    static {
        CryptoConfig.ensureProvider();
    }

    public KeyPair generateKeyPair(int groupBits) {
        try {
            BigInteger p = new BigInteger(primeForGroup(groupBits), 16);
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("DH", CryptoConfig.BC);
            kpg.initialize(new DHParameterSpec(p, G));
            return kpg.generateKeyPair();
        } catch (Exception e) {
            throw new CryptoException("Ne mogu generisati DH par ključeva (" + groupBits + " bita)", e);
        }
    }

    /** Izvodi zajedničku tajnu iz vlastitog privatnog i tuđeg javnog ključa. */
    public byte[] computeSharedSecret(PrivateKey ownPrivate, PublicKey otherPublic) {
        try {
            KeyAgreement ka = KeyAgreement.getInstance("DH", CryptoConfig.BC);
            ka.init(ownPrivate);
            ka.doPhase(otherPublic, true);
            return ka.generateSecret();
        } catch (Exception e) {
            throw new CryptoException("DH razmjena nije uspjela", e);
        }
    }

    public String encodePublicKey(PublicKey key) {
        return Base64.getEncoder().encodeToString(key.getEncoded());
    }

    public PublicKey decodePublicKey(String base64) {
        try {
            byte[] der = Base64.getDecoder().decode(base64);
            return KeyFactory.getInstance("DH", CryptoConfig.BC)
                    .generatePublic(new X509EncodedKeySpec(der));
        } catch (Exception e) {
            throw new CryptoException("Neispravan DH javni ključ", e);
        }
    }

    private String primeForGroup(int groupBits) {
        return switch (groupBits) {
            case 2048 -> P_2048;
            case 3072 -> P_3072;
            default -> throw new CryptoException("Podržane DH grupe su 2048 i 3072 bita, traženo: " + groupBits);
        };
    }
}
