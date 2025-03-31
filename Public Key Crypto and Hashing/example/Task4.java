package org.example;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HashSet;
import java.util.Set;

public class Task4 {

    public static String hashString(String input) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        // make message into bits
        byte[] digest = md.digest(input.getBytes());
        StringBuilder hexString = new StringBuilder();
        // make the hashed message display as hex
        for (byte b : digest){
            hexString.append(String.format("%02x", b));
        }
        return hexString.toString();
    }

    public static String flipBit(String input){
        char[] chars = input.toCharArray();
        chars[0] ^= 1; // flips first bit of first char
        return new String(chars);
    }

    public static void findCollision(int bits) throws NoSuchAlgorithmException {
        Set<String> hashes = new HashSet<>();
        int limit = (int) Math.pow(2, 16);
        for (int i = 0; i<limit; i++){
            String testString = String.valueOf(i);
            // (bits/4) represents the length of the truncated hash in hex
            String hash = hashString(testString).substring(0, bits/4);
            if (hashes.contains(hash)){
                System.out.println("Collision found for string " + testString + " with hash " + hash);
                return;
            }
            hashes.add(hash);
        }
        System.out.println("No collision found within limit");
    }

    public static void main(String[] args) throws NoSuchAlgorithmException {
        String str1 = "Hello World!";
        System.out.println("String: " +str1);
        String str2 = flipBit(str1);
        System.out.println("Flipped bit string: " +str2);
        System.out.println("Hashed string: " + hashString(str1));
        System.out.println("Hashed flipped bit string: " + hashString(str2));
        findCollision(8);
    }
}
