package com.example;

import java.math.BigInteger;

public class Main {
    public static void main(String[] args) {
        RSAKeyPairGenerator generator = new RSAKeyPairGenerator();
        Key publicKey = generator.getPublicKey();
        Key privateKey = generator.getPrivateKey();

        System.out.println("Clau pública (e, n):");
        System.out.println("  e = " + publicKey.exponent());
        System.out.println("  n = " + publicKey.modulus());
        System.out.println("  bits de n = " + publicKey.modulus().bitLength());
        System.out.println("Clau privada (d, n):");
        System.out.println("  d = " + privateKey.exponent());
        System.out.println("  n = " + privateKey.modulus());

        RSACipherService cipher = new RSACipherService();
        String text = "Hola, RSA! Xifrat amb accents: àèéíòóú";
        BigInteger cipherText = cipher.encryptText(text, publicKey);
        String decrypted = cipher.decryptText(cipherText, privateKey);

        System.out.println("Text original:   " + text);
        System.out.println("Text xifrat:     " + cipherText);
        System.out.println("Text desxifrat:  " + decrypted);
        System.out.println("Coincideixen:    " + text.equals(decrypted));
    }
}
