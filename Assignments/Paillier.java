package P;

import javax.swing.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.math.*;
import java.security.SecureRandom;
import java.util.*;
public class Paillier {

    static Paillier Paillier = new Paillier();
    private static final int KEY_SIZE = 512;
    private static JPanel jPanel;
    private static JFrame jFrame;
    private static JLabel jLabel0, jLabel1, jLabel2;

    private static JButton button1, button2, button3, button4, button5, button6, button7, button8, button9;
    private static JTextField jTextField1, jTextField2, jTextField3, jTextField4, jTextField5, jTextField6, jTextField7, jTextField8, jTextField9, jTextField10, jTextField11;

    BigInteger m1, m2, em1, em2, product_em1em2, sum_m1m2, prod_m1m2, expo_em1m2;
    private JLabel resultLabel;

    /**
     * p and q are two large primes.
     * lambda = lcm(p-1, q-1) = (p-1)*(q-1)/gcd(p-1, q-1).
     */
    private BigInteger p, q, lambda;
    /**
     * n = p*q, where p and q are two large primes.
     */
    public BigInteger n;
    /**
     * nsquare = n*n
     */
    public BigInteger nsquare;
    /**
     * a random integer in Z*_{n^2} where gcd (L(g^lambda mod n^2), n) = 1.
     */
    private BigInteger g;
    /**
     * number of bits of modulus
     */
    private int bitLength;

    /**
     * Constructs an instance of the Paillier cryptosystem.
     *
     * @param bitLengthVal number of bits of modulus
     * @param certainty    The probability that the new BigInteger represents a prime number will exceed (1 - 2^(-certainty)). The execution time of this constructor is proportional to the value of this parameter.
     */
    public Paillier(int bitLengthVal, int certainty) {
        KeyGeneration(bitLengthVal, certainty);
    }

    /**
     * Constructs an instance of the Paillier cryptosystem with 512 bits of modulus and at least 1-2^(-64) certainty of primes generation.
     */
    public Paillier() {
        KeyGeneration(512, 64);
    }

    /**
     * Sets up the public key and private key.
     *
     * @param bitLengthVal number of bits of modulus.
     * @param certainty    The probability that the new BigInteger represents a prime number will exceed (1 - 2^(-certainty)). The execution time of this constructor is proportional to the value of this parameter.
     */
    public void KeyGeneration(int bitLengthVal, int certainty) {
        bitLength = bitLengthVal;
        /*Constructs two randomly generated positive BigIntegers that are probably prime, with the specified bitLength and certainty.*/
        p = new BigInteger(bitLength / 2, certainty, new Random());
        q = new BigInteger(bitLength / 2, certainty, new Random());

        n = p.multiply(q);
        nsquare = n.multiply(n);

        g = new BigInteger("2");
        lambda = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE)).divide(
                p.subtract(BigInteger.ONE).gcd(q.subtract(BigInteger.ONE)));
        /* check whether g is good.*/
        if (g.modPow(lambda, nsquare).subtract(BigInteger.ONE).divide(n).gcd(n).intValue() != 1) {
            System.out.println("g is not good. Choose g again.");
            System.exit(1);
        }
    }

    /**
     * Encrypts plaintext m. ciphertext c = g^m * r^n mod n^2. This function explicitly requires random input r to help with encryption.
     *
     * @param m plaintext as a BigInteger
     * @param r random plaintext to help with encryption
     * @return ciphertext as a BigInteger
     */
    public BigInteger Encryption(BigInteger m, BigInteger r) {
        return g.modPow(m, nsquare).multiply(r.modPow(n, nsquare)).mod(nsquare);
    }

    /**
     * Encrypts plaintext m. ciphertext c = g^m * r^n mod n^2. This function automatically generates random input r (to help with encryption).
     *
     * @param m plaintext as a BigInteger
     * @return ciphertext as a BigInteger
     */
    public BigInteger Encryption(BigInteger m) {
        BigInteger r = new BigInteger(bitLength, new Random());
        return g.modPow(m, nsquare).multiply(r.modPow(n, nsquare)).mod(nsquare);

    }

    /**
     * Decrypts ciphertext c. plaintext m = L(c^lambda mod n^2) * u mod n, where u = (L(g^lambda mod n^2))^(-1) mod n.
     *
     * @param c ciphertext as a BigInteger
     * @return plaintext as a BigInteger
     */
    public BigInteger Decryption(BigInteger c) {
        BigInteger u = g.modPow(lambda, nsquare).subtract(BigInteger.ONE).divide(n).modInverse(n);
        return c.modPow(lambda, nsquare).subtract(BigInteger.ONE).divide(n).multiply(u).mod(n);
    }

    public BigInteger modPow(BigInteger base, BigInteger exponent) {
        return base.modPow(exponent, nsquare);
    }
}