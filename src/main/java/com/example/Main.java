package com.example;

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
    }
}
