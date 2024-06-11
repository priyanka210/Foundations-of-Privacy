/**
 * This program is free software: you can redistribute it and/or modify it 
 * under the terms of the GNU General Public License as published by the Free 
 * Software Foundation, either version 3 of the License, or (at your option) 
 * any later version. 
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT 
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or 
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for 
 * more details. 
 *
 * You should have received a copy of the GNU General Public License along with 
 * this program.  If not, see <http://www.gnu.org/licenses/>.
 */

import javax.swing.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.math.*;
import java.security.SecureRandom;
import java.util.*;
public class Paillier_GUI implements ActionListener {

    static Paillier_GUI paillier_GUI = new Paillier_GUI();
    private static final int KEY_SIZE = 512;
    private static JPanel jPanel;
    private static JFrame jFrame;
    private static JLabel jLabel0, jLabel1,jLabel2;

    private static JButton button1,button2, button3, button4, button5, button6, button7, button8, button9;
    private static JTextField jTextField1, jTextField2, jTextField3, jTextField4, jTextField5, jTextField6, jTextField7, jTextField8, jTextField9, jTextField10, jTextField11;

    BigInteger m1, m2, em1, em2, product_em1em2, sum_m1m2, prod_m1m2, expo_em1m2;

    /**
     * p and q are two large primes. 
     * lambda = lcm(p-1, q-1) = (p-1)*(q-1)/gcd(p-1, q-1).
     */
    private BigInteger p,  q,  lambda;
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
     * Constructs an instance of the Paillier_GUI cryptosystem.
     * @param bitLengthVal number of bits of modulus
     * @param certainty The probability that the new BigInteger represents a prime number will exceed (1 - 2^(-certainty)). The execution time of this constructor is proportional to the value of this parameter.
     */
    public Paillier_GUI(int bitLengthVal, int certainty) {
        KeyGeneration(bitLengthVal, certainty);
    }

    /**
     * Constructs an instance of the Paillier_GUI cryptosystem with 512 bits of modulus and at least 1-2^(-64) certainty of primes generation.
     */
    public Paillier_GUI() {
        KeyGeneration(512, 64);
    }

    /**
     * Sets up the public key and private key.
     * @param bitLengthVal number of bits of modulus.
     * @param certainty The probability that the new BigInteger represents a prime number will exceed (1 - 2^(-certainty)). The execution time of this constructor is proportional to the value of this parameter.
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
     * @param m plaintext as a BigInteger
     * @param r random plaintext to help with encryption
     * @return ciphertext as a BigInteger
     */
    public BigInteger Encryption(BigInteger m, BigInteger r) {
        return g.modPow(m, nsquare).multiply(r.modPow(n, nsquare)).mod(nsquare);
    }

    /**
     * Encrypts plaintext m. ciphertext c = g^m * r^n mod n^2. This function automatically generates random input r (to help with encryption).
     * @param m plaintext as a BigInteger
     * @return ciphertext as a BigInteger
     */
    public BigInteger Encryption(BigInteger m) {
        BigInteger r = new BigInteger(bitLength, new Random());
        return g.modPow(m, nsquare).multiply(r.modPow(n, nsquare)).mod(nsquare);

    }

    /**
     * Decrypts ciphertext c. plaintext m = L(c^lambda mod n^2) * u mod n, where u = (L(g^lambda mod n^2))^(-1) mod n.
     * @param c ciphertext as a BigInteger
     * @return plaintext as a BigInteger
     */
    public BigInteger Decryption(BigInteger c) {
        BigInteger u = g.modPow(lambda, nsquare).subtract(BigInteger.ONE).divide(n).modInverse(n);
        return c.modPow(lambda, nsquare).subtract(BigInteger.ONE).divide(n).multiply(u).mod(n);
    }

    /**
     * main function
     * @param str intput string
     */
    public static void main(String[] str) {
        /* instantiating an object of Paillier_GUI cryptosystem*/


        /* instantiating two plaintext msgs*/
        jPanel = new JPanel();

        jFrame = new JFrame();
        jFrame.setSize(450,300);
        jFrame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);

        jFrame.add(jPanel);
        jPanel.setLayout(null);

        jLabel0 = new JLabel("Paillier Homomorphic Encryption");
        jLabel0.setBounds(130,5,280,20);
        jPanel.add(jLabel0);

        jLabel1 = new JLabel("m1 = ");
        jLabel1.setBounds(10,30,50,20);
        jPanel.add(jLabel1);

        jTextField1 = new JTextField(20);
        jTextField1.setBounds(60,30,150,20);
        jPanel.add(jTextField1);

        jLabel2 = new JLabel("m2 = ");
        jLabel2.setBounds(230,30,50,20);
        jPanel.add(jLabel2);

        jTextField2 = new JTextField(20);
        jTextField2.setBounds(280,30,150,20);
        jPanel.add(jTextField2);

        button1 = new JButton("Encrypt m1");
        button1.setBounds(10,50,150,20);
        button1.addActionListener(new Paillier_GUI());
        jPanel.add(button1);

        jTextField3 = new JTextField(20);
        jTextField3.setBounds(180,50,250,20);
        jPanel.add(jTextField3);

        button2 = new JButton("Encrypt m2");
        button2.setBounds(10,70,150,20);
        button2.addActionListener(new Paillier_GUI());
        jPanel.add(button2);

        jTextField4 = new JTextField(20);
        jTextField4.setBounds(180,70,250,20);
        jPanel.add(jTextField4);

        button3 = new JButton("Decrypt m1");
        button3.setBounds(10,90,150,20);
        button3.addActionListener(new Paillier_GUI());
        jPanel.add(button3);

        jTextField5 = new JTextField(20);
        jTextField5.setBounds(180,90,250,20);
        jPanel.add(jTextField5);

        button4 = new JButton("Decrypt m2");
        button4.setBounds(10,110,150,20);
        button4.addActionListener(new Paillier_GUI());
        jPanel.add(button4);

        jTextField6 = new JTextField(20);
        jTextField6.setBounds(180,110,250,20);
        jPanel.add(jTextField6);

        button5 = new JButton("em1*em2");
        button5.setBounds(10,130,150,20);
        button5.addActionListener(new Paillier_GUI());
        jPanel.add(button5);

        jTextField7 = new JTextField(20);
        jTextField7.setBounds(180,130,250,20);
        jPanel.add(jTextField7);

        button6 = new JButton("Sum m1+m2");
        button6.setBounds(10,150,150,20);
        button6.addActionListener(new Paillier_GUI());
        jPanel.add(button6);

        jTextField8 = new JTextField(20);
        jTextField8.setBounds(180,150,250,20);
        jPanel.add(jTextField8);

        button7 = new JButton("Decrypted Sum");
        button7.setBounds(10,170,150,20);
        button7.addActionListener(new Paillier_GUI());
        jPanel.add(button7);

        jTextField9 = new JTextField(20);
        jTextField9.setBounds(180,170,250,20);
        jPanel.add(jTextField9);

        button8 = new JButton("Product m1*m2");
        button8.setBounds(10,190,150,20);
        button8.addActionListener(new Paillier_GUI());
        jPanel.add(button8);

        jTextField10 = new JTextField(20);
        jTextField10.setBounds(180,190,250,20);
        jPanel.add(jTextField10);

        button9 = new JButton("Decrypted Product");
        button9.setBounds(10,210,150,20);
        button9.addActionListener(new Paillier_GUI());
        jPanel.add(button9);

        jTextField11 = new JTextField(20);
        jTextField11.setBounds(180,210,250,20);
        jPanel.add(jTextField11);

        jFrame.setVisible(true);

    }

    @Override
    public void actionPerformed(ActionEvent e) {
        if(e.getSource() == button1) {
            m1 = new BigInteger(jTextField1.getText());
            em1 = paillier_GUI.Encryption(m1);
            jTextField3.setText(em1.toString());

        }
        if(e.getSource() == button2) {
            m2 = new BigInteger(jTextField2.getText());
            em2 = paillier_GUI.Encryption(m2);
            jTextField4.setText(em2.toString());

        }
        if(e.getSource() == button3) {
            em1 = new BigInteger(jTextField3.getText());
            jTextField5.setText(paillier_GUI.Decryption(em1).toString());
        }
        if(e.getSource() == button4) {
            em2 = new BigInteger(jTextField4.getText());
            jTextField6.setText(paillier_GUI.Decryption(em2).toString());

        }
        if(e.getSource() == button5) {
            em1 = new BigInteger(jTextField3.getText());
            em2 = new BigInteger(jTextField4.getText());
            product_em1em2 = em1.multiply(em2).mod(paillier_GUI.nsquare);
            jTextField7.setText(product_em1em2.toString());

        }
        if(e.getSource() == button6) {
            m1 = new BigInteger(jTextField1.getText());
            m2 = new BigInteger(jTextField2.getText());
            sum_m1m2 = m1.add(m2).mod(paillier_GUI.n);
            jTextField8.setText(sum_m1m2.toString());

        }
        if(e.getSource() == button7) {
            product_em1em2 = new BigInteger(jTextField7.getText());
            jTextField9.setText(paillier_GUI.Decryption(product_em1em2).toString());

        }
        if(e.getSource() == button8) {
            m1 = new BigInteger(jTextField1.getText());
            m2 = new BigInteger(jTextField2.getText());
            prod_m1m2 = m1.multiply(m2).mod(paillier_GUI.n);
            jTextField10.setText(prod_m1m2.toString());

        }
        if(e.getSource() == button9) {
            em1 = new BigInteger(jTextField3.getText());
            m2 = new BigInteger(jTextField2.getText());
            expo_em1m2 = em1.modPow(m2, paillier_GUI.nsquare);
            jTextField11.setText(paillier_GUI.Decryption(expo_em1m2).toString());

        }

    }
}