package com.example;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * Signa i verifica documents amb RSA sobre el seu resum SHA-256.
 */
public class RSASignatureService {

    public BigInteger calculateHash(String text) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hashBytes = digest.digest(text.getBytes(StandardCharsets.UTF_8));
            return new BigInteger(1, hashBytes);
        } catch (NoSuchAlgorithmException e) {
            // Tota implementació de Java ha de suportar SHA-256.
            throw new IllegalStateException("SHA-256 no disponible", e);
        }
    }

    /** S = H^d mod n */
    public BigInteger sign(String text, Key privateKey) {
        BigInteger hash = calculateHash(text);
        return hash.modPow(privateKey.exponent(), privateKey.modulus());
    }

    /** Compara H1 = SHA-256(text) amb H2 = S^e mod n */
    public boolean verify(String text, BigInteger signature, Key publicKey) {
        BigInteger h1 = calculateHash(text);
        BigInteger h2 = signature.modPow(publicKey.exponent(), publicKey.modulus());
        return h1.equals(h2);
    }
}
