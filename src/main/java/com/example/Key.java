package com.example;

import java.math.BigInteger;

/**
 * Clau RSA (pública o privada): un exponent i el mòdul n.
 */
public record Key(BigInteger exponent, BigInteger modulus) {}
