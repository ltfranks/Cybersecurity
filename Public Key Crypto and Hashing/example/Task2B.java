package org.example;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.security.*;
import java.util.Arrays;

public class Task2B {
    private BigInteger p, g, privateKey, publicKey;
    // this object produces a random number
    private SecureRandom rng = new SecureRandom();

    public Task2B(BigInteger p, BigInteger g) {
        this.p = p;
        this.g = g;
        // private key is random for both Alice and Bob
        this.privateKey = new BigInteger(p.bitLength(), rng);
        // each public key is generated with the random private key by doing
        // modPow => (g^privateKey)mod(p)
        this.publicKey = g.modPow(privateKey, p);
    }

    public BigInteger computeSharedSecretKey(BigInteger otherPublicKey) {
        return otherPublicKey.modPow(privateKey, p);
    }

    // public key can be sent knowingly
    public BigInteger getPublicKey() {
        return publicKey;
    }

    public static byte[] truncateTo16Bytes(byte[] original) {
        return Arrays.copyOf(original, 16);
    }


    public static byte[] symmetricKey(BigInteger sharedSecret) throws NoSuchAlgorithmException {
        MessageDigest SHA256 = MessageDigest.getInstance("SHA-256");
        return SHA256.digest(sharedSecret.toByteArray());
    }
    public BigInteger malloryModify(){
        return this.p;
    }

    public static void main(String[] args) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        BigInteger p = new BigInteger("37");
        BigInteger tamperedG = p.subtract(BigInteger.ONE);

        Task2B alice = new Task2B(p, tamperedG);
        Task2B bob = new Task2B(p, tamperedG);
        Task2B mallory = new Task2B(p, tamperedG);

        // Here Mallory intercepts the numbers Alice and Bob
        // sent to each-other and makes them both equal to P (public key)

        BigInteger aliceSecret = alice.computeSharedSecretKey(bob.getPublicKey());
        BigInteger bobSecret = bob.computeSharedSecretKey(alice.getPublicKey());
        // mallory knows the shared secret key will be either 1 or p-1
        BigInteger mallorySharedSecret1 = BigInteger.ONE;
        BigInteger mallorySharedSecret2 = p.subtract(BigInteger.ONE);

        System.out.println("Alice's Secret: " + aliceSecret);
        System.out.println("Bob's Secret: " + bobSecret);

        // From here the AES pieces are made to encrypt and decrypt messages
        // Initialization Vector (IV)
        // Key (symmetricKey) - made with the Secure Hash Algorithm (SHA-256)

        // Secure Hash Algorithm to get symmetric key
        byte[] aliceSymmetricKey = symmetricKey(aliceSecret);
        byte[] bobSymmetricKey = symmetricKey(bobSecret);
        // Decrypting Alice's message using both possible shared secrets
        byte[] mallorySymmetricKey1 = symmetricKey(mallorySharedSecret1);
        byte[] mallorySymmetricKey2 = symmetricKey(mallorySharedSecret2);

        SecretKeySpec aliceKeySpec = new SecretKeySpec(aliceSymmetricKey, "AES");
        SecretKeySpec bobKeySpec = new SecretKeySpec(bobSymmetricKey, "AES");
        SecretKeySpec malloryKeySpec1 = new SecretKeySpec(mallorySymmetricKey1, "AES");
        SecretKeySpec malloryKeySpec2 = new SecretKeySpec(mallorySymmetricKey2, "AES");
        IvParameterSpec ivParameter = new IvParameterSpec(new byte[16]);

        // encrypting Alice's message
        String aliceSentMessage = "Hello, I'm Alice";
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        // passing parameters into cypher block to encrypt message... iv, k
        cipher.init(Cipher.ENCRYPT_MODE, aliceKeySpec, ivParameter);
        byte[] aliceCiphertext = cipher.doFinal(aliceSentMessage.getBytes());

        // encrypting Bob's message
        String bobSentText = "oHayo Alice! Nice to meet you! Your message was received.";
        cipher.init(Cipher.ENCRYPT_MODE, bobKeySpec, ivParameter);
        byte[] bobCipherText = cipher.doFinal(bobSentText.getBytes());

        // bob goes into decrypt mode and deciphers Alice's text
        cipher.init(Cipher.DECRYPT_MODE, bobKeySpec, ivParameter);
        byte[] aliceDecryptedMessage = cipher.doFinal(aliceCiphertext);
        System.out.println("Alice's sent message: " + aliceSentMessage);
        System.out.println("Bob's deciphered message from Alice: " + new String(aliceDecryptedMessage));

        // Alice goes into decrypt mode and deciphers Bob's text
        cipher.init(Cipher.DECRYPT_MODE, aliceKeySpec, ivParameter);
        byte[] bobDecryptedMessage = cipher.doFinal(bobCipherText);
        System.out.println("Bob's sent message: " + bobSentText);
        System.out.println("Alice's deciphered message from Bob: " + new String(bobDecryptedMessage));

        System.out.println();
        cipher.init(Cipher.DECRYPT_MODE, malloryKeySpec1, ivParameter);
        try {
            byte[] MalAliceDecryptedMessage1 = cipher.doFinal(aliceCiphertext);
            System.out.println("Mallory decrypted Alice's Message with Key 1: " + new String(MalAliceDecryptedMessage1));
        } catch (Exception e) {
            System.out.println("Mallory could not decrypt Alice's message with Key 1.");
        }

        cipher.init(Cipher.DECRYPT_MODE, malloryKeySpec2, ivParameter);
        try {
            byte[] MalAliceDecryptedMessage2 = cipher.doFinal(aliceCiphertext);
            System.out.println("Mallory decrypted Alice's Message with Key 2: " + new String(MalAliceDecryptedMessage2));
        } catch (Exception e) {
            System.out.println("Mallory could not decrypt Alice's message with Key 2.");
        }

        cipher.init(Cipher.DECRYPT_MODE, malloryKeySpec1, ivParameter);
        try {
            byte[] MalBobDecryptedMessage1 = cipher.doFinal(bobCipherText);
            System.out.println("Mallory decrypted Bob's Message with Key 1: " + new String(MalBobDecryptedMessage1));
        } catch (Exception e) {
            System.out.println("Mallory could not decrypt bob's message with Key 1.");
        }

        cipher.init(Cipher.DECRYPT_MODE, malloryKeySpec2, ivParameter);
        try {
            byte[] MalBobDecryptedMessage2 = cipher.doFinal(bobCipherText);
            System.out.println("Mallory decrypted Bob's Message with Key 2: " + new String(MalBobDecryptedMessage2));
        } catch (Exception e) {
            System.out.println("Mallory could not decrypt bob's message with Key 2.");
        }


    }
}