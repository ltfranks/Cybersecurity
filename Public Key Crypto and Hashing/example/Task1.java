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

public class Task1 {
    private BigInteger p, g, privateKey, publicKey;
    // this object produces a random number
    private SecureRandom rng = new SecureRandom();

    public Task1(BigInteger p, BigInteger g) {
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

    public static void main(String[] args) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        BigInteger p = new BigInteger("37");
        BigInteger g = new BigInteger("5");

        Task1 alice = new Task1(p, g);
        Task1 bob = new Task1(p, g);

        BigInteger aliceSecret = alice.computeSharedSecretKey(bob.getPublicKey());
        BigInteger bobSecret = bob.computeSharedSecretKey(alice.getPublicKey());
        System.out.println("Alice's Secret: " + aliceSecret);
        System.out.println("Bob's Secret: " + bobSecret);

        // From here the AES pieces are made to encrypt and decrypt messages
        // Initialization Vector (IV)
        // Key (symmetricKey) - made with the Secure Hash Algorithm (SHA-256)

        // Secure Hash Algorithm to get symmetric key
        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
        byte[] symmetricKey = truncateTo16Bytes(sha256.digest(aliceSecret.toByteArray()));

        String aliceSentMessage = "Hello, I'm Alice";
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        SecretKeySpec keySpec = new SecretKeySpec(symmetricKey, "AES");
        IvParameterSpec ivParameter = new IvParameterSpec(new byte[16]);
        // passing parameters into cypher block to encrypt message... iv, k
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivParameter);
        byte[] aliceCiphertext = cipher.doFinal(aliceSentMessage.getBytes());

        // bob goes into decrypt mode and deciphers Alice's text
        cipher.init(Cipher.DECRYPT_MODE, keySpec, ivParameter);
        byte[] aliceDecryptedMessage = cipher.doFinal(aliceCiphertext);
        System.out.println("Alice's sent message: " + aliceSentMessage);
        System.out.println("Bob's deciphered message from Alice: " + new String(aliceDecryptedMessage));

        String bobSentText = "oHayo Alice! Nice to meet you! Your message was received.";
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivParameter);
        byte[] bobCipherText = cipher.doFinal(bobSentText.getBytes());

        // Alice goes into decrypt mode and deciphers Bob's text
        cipher.init(Cipher.DECRYPT_MODE, keySpec, ivParameter);
        byte[] bobDecryptedMessage = cipher.doFinal(bobCipherText);
        System.out.println("Bob's sent message: " + bobSentText);
        System.out.println("Alice's deciphered message from Bob: " + new String(bobDecryptedMessage));

    }
}