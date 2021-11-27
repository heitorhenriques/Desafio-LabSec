/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package primeiroprograma;

import java.io.BufferedWriter;
import java.io.FileInputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.security.DigestInputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;





public class FuncaoHash {
  public static void main(String args[])throws NoSuchAlgorithmException, IOException {
        BufferedWriter writer = new BufferedWriter(new FileWriter("output.txt"));
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        String hex = checksum("08616457b627ed8eb8ae66ef59c212da.jpg", md);
        System.out.println(hex);
        writer.write(hex);
        writer.close();
    }

    private static String checksum(String filepath, MessageDigest md) throws IOException {

        // file hashing with DigestInputStream
        try (DigestInputStream dis = new DigestInputStream(new FileInputStream(filepath), md)) {
            while (dis.read() != -1) ; //empty loop to clear the data
            md = dis.getMessageDigest();
        }

        // bytes to hex
        StringBuilder result = new StringBuilder();
        for (byte b : md.digest()) {
            result.append(String.format("%02x", b));
        }
        return result.toString();

    }

}
   
