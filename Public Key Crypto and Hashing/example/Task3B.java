package org.example;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.*;

public class Task3B {
    public static void main(String[] args) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        BigInteger e = new BigInteger("65537");
        // Java class that generates public/private keys for specific algorithm
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair keyPair = kpg.generateKeyPair();
        // java interface that represents an RSA public/private key.
        // provided methods for getting/setting key's:
        // modulus, public exponent, and private exponent
        BigInteger n = ((java.security.interfaces.RSAPublicKey) keyPair.getPublic()).getModulus();
        BigInteger d = ((java.security.interfaces.RSAPrivateKey) keyPair.getPrivate()).getPrivateExponent();

        // Alice sends encrypted s as c to Bob
        BigInteger s_a = new BigInteger(128, new SecureRandom());
        BigInteger c = s_a.modPow(e, n);

        // Mallory intercepts c and makes it c'
        // c' = c*r^e(mod(n))
        BigInteger r = new BigInteger(130, new SecureRandom());
        BigInteger cPrime = c.multiply(r.modPow(e, n));

        // Bob decrypts cPrime
        BigInteger s_b = cPrime.modPow(d, n);

        // Bob computes k using SHA256
        MessageDigest SHA256 = MessageDigest.getInstance("SHA-256");
        byte[] k = SHA256.digest(s_b.toByteArray());

        // Bob decrypts message m using k
        String m = "Hi Bob";
        SecretKeySpec keySpec = new SecretKeySpec(k, "AES");
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        IvParameterSpec iv = new IvParameterSpec(new byte[16]);
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, iv);
        byte[] c_0 = cipher.doFinal(m.getBytes(StandardCharsets.UTF_8));

        // since malory knows how c to c' was manipulated
        // she can figure the relationship between s_a to s_b
        // and compute s_b herself
        BigInteger mallory_s_b = s_a.multiply(r).mod(n);
        byte[] malloryK = SHA256.digest(mallory_s_b.toByteArray());

        // Mallory decrypts c_0 using her version of k
        SecretKeySpec malloryKeySpec = new SecretKeySpec(malloryK, "AES");
        cipher.init(Cipher.DECRYPT_MODE, malloryKeySpec, iv);
        byte[] mallory_decryptedMessage = cipher.doFinal(c_0);
        String mallory_decryptedText = new String(mallory_decryptedMessage, StandardCharsets.UTF_8);
        System.out.println("Original message by Bob: " + m);
        System.out.println("Decrypted message from Bob by Mallory: " + mallory_decryptedText);



    }
}