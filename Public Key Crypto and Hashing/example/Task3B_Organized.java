package org.example;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.*;

public class Task3B_Organized {

    private static final BigInteger E = new BigInteger("65537");

    public static void main(String[] args) throws Exception {
        // Generate RSA KeyPair
        KeyPair keyPair = generateRSAKeyPair();

        BigInteger modulus = ((java.security.interfaces.RSAPublicKey) keyPair.getPublic()).getModulus();
        BigInteger privateKey = ((java.security.interfaces.RSAPrivateKey) keyPair.getPrivate()).getPrivateExponent();

        // Alice sends encrypted message to Bob
        BigInteger originalMessage = new BigInteger(128, new SecureRandom());
        BigInteger encryptedMessage = originalMessage.modPow(E, modulus);

        // Mallory intercepts and modifies the encrypted message
        BigInteger r = new BigInteger(130, new SecureRandom());
        BigInteger modifiedEncryptedMessage = encryptedMessage.multiply(r.modPow(E, modulus));

        // Bob decrypts the intercepted message
        BigInteger decryptedByBob = modifiedEncryptedMessage.modPow(privateKey, modulus);
        byte[] keyUsedByBob = deriveKeyFromMessage(decryptedByBob);

        // Bob encrypts a new message using AES
        String newMessage = "Hi Bob";
        byte[] aesEncryptedMessage = encryptAESMessage(newMessage, keyUsedByBob);

        // Mallory derives key from known original and r
        BigInteger keyDerivedByMallory = originalMessage.multiply(r).mod(modulus);
        byte[] malloryKey = deriveKeyFromMessage(keyDerivedByMallory);

        // Mallory decrypts Bob's AES encrypted message
        String decryptedByMallory = decryptAESMessage(aesEncryptedMessage, malloryKey);
        System.out.println("Original message by Bob: " + newMessage);
        System.out.println("Decrypted message from Bob by Mallory: " + decryptedByMallory);
    }

    private static KeyPair generateRSAKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        return keyPairGenerator.generateKeyPair();
    }

    private static byte[] deriveKeyFromMessage(BigInteger message) throws NoSuchAlgorithmException {
        MessageDigest SHA256 = MessageDigest.getInstance("SHA-256");
        return SHA256.digest(message.toByteArray());
    }

    private static byte[] encryptAESMessage(String message, byte[] key) throws Exception {
        SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        IvParameterSpec iv = new IvParameterSpec(new byte[16]);  // Using a zero IV for simplicity
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, iv);
        return cipher.doFinal(message.getBytes(StandardCharsets.UTF_8));
    }

    private static String decryptAESMessage(byte[] encryptedMessage, byte[] key) throws Exception {
        SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        IvParameterSpec iv = new IvParameterSpec(new byte[16]);  // Using a zero IV for simplicity
        cipher.init(Cipher.DECRYPT_MODE, keySpec, iv);
        byte[] decryptedBytes = cipher.doFinal(encryptedMessage);
        return new String(decryptedBytes, StandardCharsets.UTF_8);
    }
}
