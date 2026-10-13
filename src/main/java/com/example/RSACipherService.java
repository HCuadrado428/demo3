package com.example;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

/**
 * Xifra i desxifra missatges amb RSA mitjançant exponenciació modular.
 */
public class RSACipherService {

    /** C = M^e mod n */
    public BigInteger encrypt(BigInteger message, Key publicKey) {
        // RSA només pot xifrar valors 0 <= M < n; altrament es perd informació.
        if (message.signum() < 0 || message.compareTo(publicKey.modulus()) >= 0) {
            throw new IllegalArgumentException("El missatge ha de complir 0 <= M < n");
        }
        return message.modPow(publicKey.exponent(), publicKey.modulus());
    }

    /** M = C^d mod n */
    public BigInteger decrypt(BigInteger cipherText, Key privateKey) {
        return cipherText.modPow(privateKey.exponent(), privateKey.modulus());
    }

    public BigInteger encryptText(String text, Key publicKey) {
        byte[] bytes = text.getBytes(StandardCharsets.UTF_8);
        BigInteger message = new BigInteger(1, bytes); // El '1' indica que és un nombre positiu
        return encrypt(message, publicKey);
    }

    public String decryptText(BigInteger cipherText, Key privateKey) {
        byte[] bytes = decrypt(cipherText, privateKey).toByteArray();
        // toByteArray() afegeix un byte 0 de signe si el bit alt és 1; cal treure'l.
        if (bytes.length > 1 && bytes[0] == 0) {
            bytes = Arrays.copyOfRange(bytes, 1, bytes.length);
        }
        return new String(bytes, StandardCharsets.UTF_8);
    }
}
