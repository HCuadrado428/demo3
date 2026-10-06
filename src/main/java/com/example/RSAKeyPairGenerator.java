package com.example;

import java.math.BigInteger;
import java.security.SecureRandom;

/**
 * Genera un parell de claus RSA de 2048 bits (p i q de 1024 bits cadascun).
 */
public class RSAKeyPairGenerator {

    private static final int PRIME_BIT_LENGTH = 1024;
    private static final BigInteger E = BigInteger.valueOf(65537);

    private final Key publicKey;
    private final Key privateKey;

    public RSAKeyPairGenerator() {
        SecureRandom random = new SecureRandom();

        BigInteger p, q, phi;
        do {
            p = BigInteger.probablePrime(PRIME_BIT_LENGTH, random);
            q = BigInteger.probablePrime(PRIME_BIT_LENGTH, random);
            phi = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));
            // p i q han de ser diferents i e ha de ser coprimer amb phi(n),
            // altrament e no té inversa modular.
        } while (p.equals(q) || !E.gcd(phi).equals(BigInteger.ONE));

        BigInteger n = p.multiply(q);
        BigInteger d = E.modInverse(phi);

        this.publicKey = new Key(E, n);
        this.privateKey = new Key(d, n);
    }

    public Key getPublicKey() {
        return publicKey;
    }

    public Key getPrivateKey() {
        return privateKey;
    }
}
