package com.mirea;

import java.io.IOException;
import java.nio.file.NoSuchFileException;
import java.security.NoSuchAlgorithmException;



public class Main {
    
    static String info[] = {
        "Functional:\n",
        "    Generate key: java Sign.jar -k <PATH for keys>\n",
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
                try {
                    filename = args[1];
                SignRSA.generateKeys(filename);
                } 
                catch (IOException e) {
                    System.out.println("ERROR: Failed to create files.");
                }
                catch (IndexOutOfBoundsException e) {
                    System.out.println("Missing arguments. Expected -k <PATH>");
                }
                
                break;
            case "-e":
                try {
                    filename = args[1];
                    privatekey = args[2];
                    SignRSA.signingFile(filename, privatekey);
                }
                catch (NoSuchFileException e) {
                    System.out.println("ERROR: file " + filename + " is not exist");
                }
                catch (IndexOutOfBoundsException e) {
                    System.out.println("Missing arguments. Expected -e <PATH> <PATH>");
                }
                break;
            case "-d":
                try {
                    filename = args[1];
                    publickey = args[2];
                    SignRSA.checkSign(filename, publickey);
                }
                catch (NoSuchFileException e) {
                    System.out.println("ERROR: file " + filename + " is not exist");
                }
                catch (IndexOutOfBoundsException e) {
                    System.out.println("Missing arguments. Expected -d <PATH> <PATH>");
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
