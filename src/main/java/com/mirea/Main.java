package com.mirea;

import java.io.File;
import java.io.IOException;
import java.nio.file.NoSuchFileException;
import java.security.NoSuchAlgorithmException;



public class Main {
    
    static String info[] = {
        "Functional:\n",
        "    Generate key: java Sign.jar -k\n",
        "    Encrypt file: java Sign.jar -e <PATH to file> <PATH to private key>\n",
        "    Decrypt file: java Sign.jar -d <PATH to file> <PATH to public key>\n"
    };

    public static void main(String[] args) throws IOException, NoSuchAlgorithmException {
        
        String filename = "";
        String privatekey = "";
        String publickey = "";

        if (args.length == 0) {
            System.out.println("Cannot detect flag <-h, -k, -e, -d>");
            for(String now : info) {
                System.out.print(now);
            }
            return;
        }

        switch (args[0]) {
            case "-h":
                for(String now : info) {
                    System.out.print(now);
                }
                break;
            case "-k":
                RSA.generateKeys();
            case "-e":
                filename = args[1];
                privatekey = args[2];
                try {
                    RSA.signingFile(filename, privatekey);
                }
                catch (NoSuchFileException e) {
                    System.out.println("ERROR: file " + filename + " is not exist");
                }
                break;
            case "-d":
                filename = args[1];
                publickey = args[2];
                try {
                    RSA.checkSign(filename, publickey);
                }
                catch (NoSuchFileException e) {
                    System.out.println("ERROR: file " + filename + " is not exist");
                }
                break;
            default:
                System.out.println("Cannot detect flag <-h, -k, -e, -d>");
                for(String now : info) {
                    System.out.print(now);
                }
                break;
        }
    }
}
