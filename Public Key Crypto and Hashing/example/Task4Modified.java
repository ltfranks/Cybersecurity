package org.example;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.*;

public class Task4Modified {

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
    // using the birthday problem
    // storing a strings random truncated hash into a hashmap
    // then brute forcing (birthday problem) and eventually finding
    // a collision with the same hash but different string value

    // only able to do this bec of truncated hash
    public static Pair<Integer, Long> findCollision(int bits) throws NoSuchAlgorithmException {
        Map<String, String> seenHashes = new HashMap<>();
        Random rng = new Random();
        String testString;
        String truncatedHash;

        long startTime = System.currentTimeMillis();
        int limit = (int) Math.pow(2, 16);
        for (int i = 0; i<limit; i++){
            testString = String.valueOf(rng.nextInt());
            // (bits/4) represents the length of the truncated hash in hex
            truncatedHash = hashString(testString).substring(0, bits/4);
            if (seenHashes.containsKey(truncatedHash)){
                long endTime = System.currentTimeMillis();
                System.out.println("Collision found");
                System.out.println("String 1: " + seenHashes.get(truncatedHash));
                System.out.println("String 2: " + testString);
                System.out.println("Truncated hash: " + truncatedHash);

                return new Pair<>(i, endTime-startTime);
            }
            seenHashes.put(truncatedHash, testString);
        }
        long endTime = System.currentTimeMillis();
        System.out.println("No collision found within limit");
        return new Pair<>(limit, endTime-startTime);
    }

    public static void main(String[] args) throws NoSuchAlgorithmException {
//        String str1 = "Hello World!";
//        System.out.println("String: " +str1);
//        String str2 = flipBit(str1);
//        System.out.println("Flipped bit string: " +str2);
//        System.out.println("Hashed string: " + hashString(str1));
//        System.out.println("Hashed flipped bit string: " + hashString(str2));
        List<Pair<Integer, Long>> results = new ArrayList<>();
        for (int bits = 8; bits <= 50; bits += 2){
            results.add(findCollision(bits));
        }
        CreateChart.createChart(results);
    }
}
