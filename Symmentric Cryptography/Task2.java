package org.example;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.security.SecureRandom;
import java.util.Arrays;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

public class Task2 {
    private static SecretKey key;
    private static IvParameterSpec ivSpec;

    static {
        try {
            KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
            keyGenerator.init(128);
            key = keyGenerator.generateKey();

            byte[] iv = new byte[16];
            new SecureRandom().nextBytes(iv);
            ivSpec = new IvParameterSpec(iv);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static byte[] submit(String userdata) throws Exception {
        userdata = URLEncoder.encode(userdata, StandardCharsets.UTF_8);
        String input = "userid=456;userdata=" + userdata + ";session-id=31337";
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);
        return cipher.doFinal(input.getBytes(StandardCharsets.UTF_8));
    }

    public static boolean verify(byte[] ciphertext) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, key, ivSpec);
        String decrypted = new String(cipher.doFinal(ciphertext), StandardCharsets.UTF_8);
        return decrypted.contains(";admin=true;");
    }

    // Method to perform bit-flipping attack (simplified example)
    public static byte[] performAttack(byte[] ciphertext) {
        // Modify ciphertext to include ";admin=true;" in the decrypted text
        // This requires knowledge of the block size and position where the change should be made
        // Example: ciphertext[desired_position] ^= desired_change;
        return ciphertext;
    }

    public static void main(String[] args) throws Exception {
        String userdata = "You’re the man now, dog";
        byte[] ciphertext = submit(userdata);

        // Perform bit-flipping attack
        ciphertext = performAttack(ciphertext);

        // Check if the attack was successful
        boolean isAdmin = verify(ciphertext);
        System.out.println("Admin Access: " + isAdmin);
    }
}
