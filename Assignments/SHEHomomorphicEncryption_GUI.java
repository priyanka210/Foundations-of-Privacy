import com.sun.xml.internal.bind.v2.runtime.output.StAXExStreamWriterOutput;
import sun.lwawt.macosx.CSystemTray;

import javax.swing.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Random;

public class SHEHomomorphicEncryption implements ActionListener {

    private static BigInteger p, q, L, N;
    private static int k0, k1, k2;
    private static Random rnd;
    private static String k2Rand, k0Rand;
    private static JPanel jPanel;
    private static JFrame jFrame;
    private static JLabel jLabel0, jLabel1,jLabel2;

    private static JButton button1,button2, button3, button4, button5, button6, button7, button8, button9, button10, button11, button12;
    private static JTextField jTextField1, jTextField2, jTextField3, jTextField4, jTextField5, jTextField6, jTextField7, jTextField8, jTextField9, jTextField10, jTextField11, jTextField12, jTextField13, jTextField14;

    // Constructor
    public SHEHomomorphicEncryption() {
        SHEHomomorphicEncryption.k0 = 128;
        SHEHomomorphicEncryption.k1 = 16;
        SHEHomomorphicEncryption.k2 = 46;
        rnd = new Random();
        k2Rand = generate(SHEHomomorphicEncryption.k2);
        k0Rand = generate(SHEHomomorphicEncryption.k0);
        generateKeys();
    }

    // Generate secret key and public parameters
    public static void generateKeys() {
        p = BigInteger.probablePrime(k0, rnd);
        q = BigInteger.probablePrime(k0, rnd);

        // generate a random number L of bit length |L| = k2
        L = new BigInteger(k2, rnd);

        // compute N = pq
        N = p.multiply(q);

        // set the public parameters
        BigInteger[] PP = { BigInteger.valueOf(k0), BigInteger.valueOf(k1), BigInteger.valueOf(k2), N };

        // set the secret key
        BigInteger[] SK = { p, q, L };

        //System.out.println("Public Parameters: " + PP[0] + ", " + PP[1] + ", " + PP[2] + ", " + PP[3]);
        //System.out.println("Secret Key: " + SK[0] + ", " + SK[1] + ", " + SK[2]);
    }


    // Encrypt plaintext m
    public static BigInteger encrypt(BigInteger m) {
        BigInteger r = new BigInteger(k2, new Random());
        BigInteger r0 = new BigInteger(k0, new Random());
//        System.out.println("r: " +r);
//        System.out.println("r0: " +r0);
        return m.add(r.multiply(L)).multiply(BigInteger.ONE.add(r0.multiply(p))).mod(N);
    }
    public static String generate(int length) {
        StringBuilder sb = new StringBuilder(length);
        for (int i = 0; i < length; i++) {
            sb.append(rnd.nextInt(2));
        }
//        System.out.println("sb.toString(): "+ sb.toString());
        return sb.toString();
    }
    // Decrypt ciphertext c
    public static BigInteger decrypt(BigInteger c) {
        return c.mod(p).mod(L);
    }

    // Homomorphic addition
    public static BigInteger homoAddition(BigInteger c1, BigInteger c2) {
        return c1.add(c2).mod(N);
    }

    // Homomorphic multiplication
    public static BigInteger homoMultiplication(BigInteger c1, BigInteger c2) {
        return c1.multiply(c2).mod(N);
    }

    // Homomorphic addition with plaintext
    public static BigInteger homoAdditionWithPlaintext(BigInteger c1, BigInteger m2) {
        return c1.add(encrypt(m2)).mod(N);
    }

    // Homomorphic multiplication with plaintext
    public static BigInteger homoMultiplicationWithPlaintext(BigInteger c1, BigInteger m2) {
        return c1.multiply(m2).mod(N);
    }

    // Main method for demonstration
    public static void main(String[] args) {
        SHEHomomorphicEncryption she = new SHEHomomorphicEncryption();

        /* instantiating two plaintext msgs*/
        jPanel = new JPanel();

        jFrame = new JFrame();
        jFrame.setSize(500,340);
        jFrame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);

        jFrame.add(jPanel);
        jPanel.setLayout(null);

        jLabel0 = new JLabel("SHE Homomorphic Encryption");
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
        jTextField2.setBounds(300,30,150,20);
        jPanel.add(jTextField2);

        button1 = new JButton("Encrypt m1");
        button1.setBounds(10,50,180,20);
        button1.addActionListener(new SHEHomomorphicEncryption());
        jPanel.add(button1);

        jTextField3 = new JTextField(20);
        jTextField3.setBounds(200,50,250,20);
        jPanel.add(jTextField3);

        button2 = new JButton("Encrypt m2");
        button2.setBounds(10,70,180,20);
        button2.addActionListener(new SHEHomomorphicEncryption());
        jPanel.add(button2);

        jTextField4 = new JTextField(20);
        jTextField4.setBounds(200,70,250,20);
        jPanel.add(jTextField4);

        button3 = new JButton("Decrypt m1");
        button3.setBounds(10,90,180,20);
        button3.addActionListener(new SHEHomomorphicEncryption());
        jPanel.add(button3);

        jTextField5 = new JTextField(20);
        jTextField5.setBounds(200,90,250,20);
        jPanel.add(jTextField5);

        button4 = new JButton("Decrypt m2");
        button4.setBounds(10,110,180,20);
        button4.addActionListener(new SHEHomomorphicEncryption());
        jPanel.add(button4);

        jTextField6 = new JTextField(20);
        jTextField6.setBounds(200,110,250,20);
        jPanel.add(jTextField6);

        button5 = new JButton("HomoAdd c1,c2");
        button5.setBounds(10,130,180,20);
        button5.addActionListener(new SHEHomomorphicEncryption());
        jPanel.add(button5);

        jTextField7 = new JTextField(20);
        jTextField7.setBounds(200,130,250,20);
        jPanel.add(jTextField7);

        button6 = new JButton("Decrypt HomoAdd c1,c2");
        button6.setBounds(10,150,180,20);
        button6.addActionListener(new SHEHomomorphicEncryption());
        jPanel.add(button6);

        jTextField8 = new JTextField(20);
        jTextField8.setBounds(200,150,250,20);
        jPanel.add(jTextField8);

        button7 = new JButton("HomoMul c1,c2");
        button7.setBounds(10,170,180,20);
        button7.addActionListener(new SHEHomomorphicEncryption());
        jPanel.add(button7);

        jTextField9 = new JTextField(20);
        jTextField9.setBounds(200,170,250,20);
        jPanel.add(jTextField9);

        button8 = new JButton("Decrypt HomoMul c1,c2");
        button8.setBounds(10,190,180,20);
        button8.addActionListener(new SHEHomomorphicEncryption());
        jPanel.add(button8);

        jTextField10 = new JTextField(20);
        jTextField10.setBounds(200,190,250,20);
        jPanel.add(jTextField10);

        button9 = new JButton("HomoAdd c1,m2");
        button9.setBounds(10,210,180,20);
        button9.addActionListener(new SHEHomomorphicEncryption());
        jPanel.add(button9);

        jTextField11 = new JTextField(20);
        jTextField11.setBounds(200,210,250,20);
        jPanel.add(jTextField11);

        button10 = new JButton("Decrypt HomoAdd c1,m2");
        button10.setBounds(10,230,180,20);
        button10.addActionListener(new SHEHomomorphicEncryption());
        jPanel.add(button10);

        jTextField12 = new JTextField(20);
        jTextField12.setBounds(200,230,250,20);
        jPanel.add(jTextField12);

        button11 = new JButton("HomoMul c1,m2");
        button11.setBounds(10,250,180,20);
        button11.addActionListener(new SHEHomomorphicEncryption());
        jPanel.add(button11);

        jTextField13 = new JTextField(20);
        jTextField13.setBounds(200,250,250,20);
        jPanel.add(jTextField13);

        button12 = new JButton("Decrypt HomoMul c1,m2");
        button12.setBounds(10,270,180,20);
        button12.addActionListener(new SHEHomomorphicEncryption());
        jPanel.add(button12);

        jTextField14 = new JTextField(20);
        jTextField14.setBounds(200,270,250,20);
        jPanel.add(jTextField14);

        jFrame.setVisible(true);

    }

    @Override
    public void actionPerformed(ActionEvent e) {
        BigInteger m1;
        BigInteger em1;
        if(e.getSource() == button1) {
            m1 = new BigInteger(jTextField1.getText());
            em1 = encrypt(m1);
            jTextField3.setText(em1.toString());

        }
        BigInteger em2;
        BigInteger m2;
        if(e.getSource() == button2) {
            m2 = new BigInteger(jTextField2.getText());
            em2 = encrypt(m2);
            jTextField4.setText(em2.toString());

        }
        if(e.getSource() == button3) {
            em1 = new BigInteger(jTextField3.getText());
            jTextField5.setText(decrypt(em1).toString());
        }
        if(e.getSource() == button4) {
            em2 = new BigInteger(jTextField4.getText());
            jTextField6.setText(decrypt(em2).toString());

        }
        BigInteger product_em1em2;
        if(e.getSource() == button5) {
            em1 = new BigInteger(jTextField3.getText());
            em2 = new BigInteger(jTextField4.getText());
            product_em1em2 = homoAddition(em1,em2);
            jTextField7.setText(product_em1em2.toString());

        }
        if(e.getSource() == button6) {
            jTextField8.setText(decrypt(new BigInteger(jTextField7.getText())).toString());

        }
        if(e.getSource() == button7) {
            em1 = new BigInteger(jTextField3.getText());
            m2 = new BigInteger(jTextField2.getText());
            BigInteger sum_m1m2 = homoMultiplication(em1,m2);
            jTextField9.setText(sum_m1m2.toString());



        }
        if(e.getSource() == button8) {
            product_em1em2 = new BigInteger(jTextField9.getText());
            jTextField10.setText(decrypt(product_em1em2).toString());

//            m1 = new BigInteger(jTextField1.getText());
//            m2 = new BigInteger(jTextField2.getText());
//            BigInteger prod_m1m2 = m1.multiply(m2).mod(N);
//            jTextField10.setText(prod_m1m2.toString());

        }
        if(e.getSource() == button9) {
            em1 = new BigInteger(jTextField3.getText());
            m2 = new BigInteger(jTextField2.getText());
            BigInteger c6 = homoAdditionWithPlaintext(em1, m2);
            jTextField11.setText(c6.toString());

        }
        if(e.getSource() == button10) {
            jTextField12.setText(decrypt(new BigInteger(jTextField11.getText())).toString());

        }

        if(e.getSource() == button11) {
            em1 = new BigInteger(jTextField3.getText());
            m2 = new BigInteger(jTextField2.getText());
            BigInteger c6 = homoMultiplicationWithPlaintext(em1, m2);
            jTextField13.setText(c6.toString());

        }
        if(e.getSource() == button12) {
            jTextField14.setText(decrypt(new BigInteger(jTextField13.getText())).toString());

        }

    }
}