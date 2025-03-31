package org.example;

import java.math.BigInteger;
import java.util.Random;

public class Task3A {
    private BigInteger n, e, d;

    public Task3A(int bits){
        BigInteger p = new BigInteger(bits/ 2, 100, new Random());
        BigInteger q = new BigInteger(bits/ 2, 100, new Random());
        this.n = p.multiply(q);
        // m = (p-1)*(q-1)
        BigInteger m = (p.subtract(BigInteger.ONE)).multiply(q.subtract(BigInteger.ONE));
        this.e = new BigInteger("65537");
        // d*e*mod(m) = 1
        this.d = e.modInverse(m);
    }

    public BigInteger encrypt(BigInteger message){
        return message.modPow(e, n);
    }

    public BigInteger decrypt(BigInteger encryptedMessage){
        return encryptedMessage.modPow(d, n);
    }

    public static void main(String[] args) {
        Task3A rsa = new Task3A(2048);
        String message = "Ohayo, I'm Luke and I'm testing RSA!";
        System.out.println("Message: " + message);

        byte[] messageInBytes = message.getBytes();
        BigInteger plainText = new BigInteger(messageInBytes);

        BigInteger encryptedMessage = rsa.encrypt(plainText);
        System.out.println("Encrypted Message: " + encryptedMessage.toString(16).toUpperCase());

        BigInteger decryptedMessage = rsa.decrypt(encryptedMessage);
        System.out.println("Decrypted Message: " + new String(decryptedMessage.toByteArray()));

    }
}
