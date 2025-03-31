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

public class Task2A {
    private BigInteger p, g, privateKey, publicKey;
    // this object produces a random number
    private SecureRandom rng = new SecureRandom();

    public Task2A(BigInteger p, BigInteger g) {
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
        BigInteger g = new BigInteger("5");

        Task2A alice = new Task2A(p, g);
        Task2A bob = new Task2A(p, g);
        Task2A mallory = new Task2A(p, g);

        // Here Mallory intercepts the numbers Alice and Bob
        // sent to each-other and makes them both equal to P (public key)

        BigInteger aliceSecret = alice.computeSharedSecretKey(bob.malloryModify());
        BigInteger bobSecret = bob.computeSharedSecretKey(alice.malloryModify());
        BigInteger malloryIntercept = mallory.computeSharedSecretKey(mallory.malloryModify());
        System.out.println("Alice's Secret: " + aliceSecret);
        System.out.println("Bob's Secret: " + bobSecret);

        // From here the AES pieces are made to encrypt and decrypt messages
        // Initialization Vector (IV)
        // Key (symmetricKey) - made with the Secure Hash Algorithm (SHA-256)

        // Secure Hash Algorithm to get symmetric key
        byte[] aliceSymmetricKey = symmetricKey(aliceSecret);
        byte[] bobSymmetricKey = symmetricKey(bobSecret);
        byte[] mallorySymmetricKey = symmetricKey(malloryIntercept);
        SecretKeySpec aliceKeySpec = new SecretKeySpec(aliceSymmetricKey, "AES");
        SecretKeySpec bobKeySpec = new SecretKeySpec(bobSymmetricKey, "AES");
        SecretKeySpec malloryKeySpec = new SecretKeySpec(mallorySymmetricKey, "AES");
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
        cipher.init(Cipher.DECRYPT_MODE, malloryKeySpec, ivParameter);
        byte[] MalAliceDecryptedMessage = cipher.doFinal(aliceCiphertext);
        byte[] MalBobDecryptedMessage = cipher.doFinal(bobCipherText);
        System.out.println("Malory got Alice's Message: " + new String(MalAliceDecryptedMessage));
        System.out.println("Malory got Bob's Message: " + new String(MalBobDecryptedMessage));


    }
}
// since alice and bob both receive shared secret s = 0, they put it
// through the hash algorithm and get the same output.
// so Mallory can do the same thing SHA(0).
// then follow the rest of the process of diffieHellman
// to decrypt any message.