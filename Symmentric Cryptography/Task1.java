package org.example;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;


public class Task1 {

    private static byte[] encryptECB(byte[] plaintext, SecretKey key) throws NoSuchPaddingException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException {
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(plaintext);
    }

    private static byte[] encryptCBC(byte[] plaintext, SecretKey key, IvParameterSpec ivSpec) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);

        return cipher.doFinal(plaintext);
    }

    private static void encryptBMPFile(String inputPath, String outputPath, boolean useCBC, SecretKey key, IvParameterSpec ivSpec) throws Exception {
        byte[] fileData = Files.readAllBytes(Paths.get(inputPath));

        // Assuming the header is 54 bytes for simplicity
        byte[] header = Arrays.copyOfRange(fileData, 0, 54);
        byte[] imageData = Arrays.copyOfRange(fileData, 54, fileData.length);

        byte[] encryptedData = useCBC ? encryptCBC(imageData, key, ivSpec) : encryptECB(imageData, key);

        // Combine header and encrypted data
        byte[] outputData = new byte[header.length + encryptedData.length];
        System.arraycopy(header, 0, outputData, 0, header.length);
        System.arraycopy(encryptedData, 0, outputData, header.length, encryptedData.length);

        Files.write(Paths.get(outputPath), outputData);
    }

    public static void main(String[] args) throws Exception {
        String inputPath = "mustang.bmp";
        String outputPathECB = "mustangECB.bmp";
        String outputPathCBC = "mustangCBC.bmp";

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(128);
        SecretKey key = keyGenerator.generateKey();

        // cbc
        byte[] iv = new byte[16];
        new SecureRandom().nextBytes(iv);
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);

        encryptBMPFile(inputPath, outputPathECB, false, key, ivParameterSpec); // For ECB
        encryptBMPFile(inputPath, outputPathCBC, true, key, ivParameterSpec);  // For CBC
    }
}