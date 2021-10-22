package com.mirea;

import java.io.*;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Random;

import com.mirea.RSA.KeyPair.PrivateKey;
import com.mirea.RSA.KeyPair.PublicKey;

public class RSA {
    

    /**
     * Класс содержащий закрытый и открытый ключ для RSA.
     */
    static class KeyPair {
        PublicKey PublicK;    // Открытый ключ
        PrivateKey PrivateK;   // Закрытый ключ

        /**
         * Структура для открытого ключа
         */
        static class PublicKey {
            BigInteger e = BigInteger.ZERO;
            BigInteger N = BigInteger.ZERO;
            
            PublicKey() {}

            PublicKey(BigInteger e, BigInteger N) {
                this.e = e;
                this.N = N;
            }
        }

        /**
         * Структура для закрытого ключа
         */
        static class PrivateKey {
            BigInteger d = BigInteger.ZERO;
            BigInteger N = BigInteger.ZERO;

            PrivateKey() {}

            PrivateKey(BigInteger d, BigInteger N) {
                this.d = d;
                this.N = N;
            }
            
        }


        KeyPair(BigInteger e, BigInteger d, BigInteger N) {
            PublicK = new PublicKey(e, N);
            PrivateK = new PrivateKey(d, N);
        }
    }

    /**
     * Возращает обратный элемент по умножению для элемента {@link V} в кольце {@link Z/M}.
     * Вычисляется с помощью Расширенного алгоритма Евклида.
     * Всегда возращает значение больше 0.
     * 
     * @author База алгоритма: https://github.com/bcgit/bc-java/blob/master/core/src/main/java/org/bouncycastle/pqc/math/ntru/euclid/BigIntEuclidean.java
     * 
     * @param V - элемент кольца
     * @param M - модуль кольца
     * @return Обратный элемент для элемента V в кольце Z\M
     */
    private static BigInteger getInverse(BigInteger V, BigInteger M) { 

        BigInteger A = V;
        BigInteger B = M;


        // Extends Eulcid Algorithm
        BigInteger x = BigInteger.ZERO;
        BigInteger lastx = BigInteger.ONE;
        BigInteger y = BigInteger.ONE;
        BigInteger lasty = BigInteger.ZERO;
        while (!B.equals(BigInteger.ZERO))
        {
            BigInteger[] quotientAndRemainder = A.divideAndRemainder(B);
            BigInteger quotient = quotientAndRemainder[0];

            BigInteger temp = B;
            A = B;
            B = quotientAndRemainder[1];

            temp = x;
            x = lastx.subtract(quotient.multiply(x));
            lastx = temp;

            temp = y;
            y = lasty.subtract(quotient.multiply(y));
            lasty = temp;
        }

        return lastx.signum() < 0 ? lastx.add(M) : lastx;
    }


    /**
     * Возвращает строку содержащую хеш-сумму для {@code file} по {@code SHA-256}  
     * @param file - дескриптор файла
     * @param sizeOfFile - количество байт, для которых нужно вычислить хеш-сумму
     * @return Строка с хеш-суммой
     * @throws IOException
     * 
     * @author https://howtodoinjava.com/java/io/sha-md5-file-checksum-hash/
     */
    public static byte[] getFileSHA256(File file, long sizeOfFile) throws IOException, NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        FileInputStream fis = new FileInputStream(file);
        
        byte[] byteArray = new byte[1];
        int bytesCount = 0; 
        int j = 0;
        while (j < sizeOfFile) {
            if ((bytesCount = fis.read(byteArray)) == -1)
                break;
            j++;
            digest.update(byteArray, 0, bytesCount);
        };
        
        fis.close();
        
        byte[] bytes = digest.digest();
        
        StringBuilder sb = new StringBuilder();
        for(int i=0; i< bytes.length ;i++)
        {
            sb.append(Integer.toString((bytes[i] & 0xff) + 0x100, 16).substring(1));
        }
        System.out.println(sb);
        
        return bytes;
    }

    /**
     * Вычисляет размер файла в байтах
     * @param path - путь до требуемого файла
     * @return Размер файла в байтах
     * @throws IOException
     */
    public static long getSizeOfFile(String path) throws IOException{ 
        return Files.size(Paths.get(path));
    }

    /**
     * Возвращает случайное простое число заданного размера.
     * Размер задается в битах и указывается целым числом в параметр {@link bitLenght}.
     * Вероятность того, что полученное число будет не простым не превышает 2^-100.
     * @param bitLength - Размер требуемого простого числа
     * @return Случайное простое число размером {@link bitLenght} бит 
     */
    public static BigInteger getRandomPrime(int bitLength) {
        return BigInteger.probablePrime(bitLength, new Random());
    }


    /**
     * Создает файлы {@code PrivateKey} и {@code PublicKey}. 
     * </p> В файле {@code PublicKey} находится 2 числа (открытая экспонента и N). Его можно передать вместе с зашифрованном сообщением.
     * </p> В файле {@code PrivateKey} находится 2 числа (закрытая экспонента и N). Его необходимо держать в секрете.
     * </p> Для удобной связи {@code PrivateKey} и {@code PublicKey} в конце названия файла написан случайный общий идентификационный номер.
     * 
     */
    public static void generateKeys() {
        BigInteger p = RSA.getRandomPrime(1024);                        // p = Простое

        BigInteger q = RSA.getRandomPrime(1024);                        // q = Простое

        BigInteger N = p.multiply(q);                                   // N = p * q
        System.out.println("N = " + N);
        
        BigInteger qMinusOne = q.subtract(new BigInteger("1"));
        BigInteger pMinusOne = p.subtract(new BigInteger("1"));
        BigInteger Euler = qMinusOne.multiply(pMinusOne);

        int i = new Random().nextInt(17 - 5) + 5;                      // Случайное целое число из диопазона[5, 32]
        BigInteger e = RSA.getRandomPrime(i);                          // Открытая экспонента
        while( !Euler.gcd(e).equals(new BigInteger("1"))) {            // e и Euler взаимно просты
            e = e.nextProbablePrime();
        }
        System.out.println("e = " + e);

        BigInteger d = RSA.getInverse(e, Euler);
        System.out.println("d = " + d);

        int id = new Random().nextInt(10000000);                        // Случайный id для названия файлов
        try (
             FileOutputStream outPublic = new FileOutputStream("PublicKey" + id);
             FileOutputStream outPrivate = new FileOutputStream("PrivateKey" + id);
             ) {

            outPublic.write(e.toString().getBytes());
            outPublic.write(new String("\n").getBytes());
            outPublic.write(N.toString().getBytes());

            outPrivate.write(d.toString().getBytes());
            outPrivate.write(new String("\n").getBytes());
            outPrivate.write(N.toString().getBytes());

            
        } catch (Exception ex) {

            File fPublic = new File("./PublicKey" + id);
            fPublic.delete();
            
            File fPrivate = new File("./PrivateKey" + id);
            fPrivate.delete();

            ex.printStackTrace();
        }
    }


    /**
     * Распаковывает файл с открытым ключом и возвращает объект {@link PublicKey}
     * @param publicKey
     * @return
     * @throws FileNotFoundException
     * @throws IOException
     */
    public static PublicKey getPublicKey(String publicKey) throws FileNotFoundException, IOException{
        PublicKey result = new PublicKey();
        try(BufferedReader in = new BufferedReader(new FileReader(publicKey));) {
            String e = in.readLine();
            String N = in.readLine();
            result.e = new BigInteger(e);
            result.N = new BigInteger(N);
        }

        return result;
    } 


    /**
     * Возвращает объект {@link PrivateKey} содержащую закрытый ключ из файла {@code privateKey} 
     * @param privateKey - путь до файла с закрытым ключом
     * @return Объект {@link PrivateKey} с закрытым ключом
     * @throws FileNotFoundException
     * @throws IOException
     */
    public static PrivateKey getPrivateKey(String privateKey) throws FileNotFoundException, IOException{
        PrivateKey result = new PrivateKey();
        try(BufferedReader in = new BufferedReader(new FileReader(privateKey));) {
            String d = in.readLine();
            String N = in.readLine();
            result.d = new BigInteger(d);
            result.N = new BigInteger(N);
        }

        return result;
    } 


    /**
     * Расшифровка массива {@code source} с помощью закрытого ключа 
     * @param d - закрытая экспонента
     * @param N - модуль
     * @param source - исходный массив в формате {@code byte}
     * @return Зашифрованный массив в формате {@link BigInteger}
     */
    public static BigInteger[] crypt(BigInteger d, BigInteger N, byte[] source) {
        BigInteger[] result = new BigInteger[source.length];

        for(int i = 0; i < source.length; i++) {
            BigInteger m = new BigInteger(Integer.toString(source[i] + 128));
            BigInteger c = m.modPow(d, N);
            result[i] = c;
        }

        return result;
    }

    /**
     * Расшифровка массива {@code source} с помощью открытого ключа
     * @param e - открытая экспонента 
     * @param N - модуль
     * @param source - зашифрованный массив в формате {@link BigInteger}
     * @return Расшифрованный массив в формате {@code byte}
     */
    public static byte[] decrypt(BigInteger e, BigInteger N, BigInteger[] source) {
        byte[] result = new byte[source.length];

        for(int i = 0; i < source.length; i++) {
            BigInteger m = source[i];
            BigInteger c = m.modPow(e, N);
            int temp = c.intValue() - 128;
            result[i] = (byte)temp;
        }

        return result;
    }

    /**
     * Переворачивает массив, переданный в качетсве параметра {@code arr} 
     * @param arr - исходный массив
     */
    private static void invertArray(byte[] arr) {
        for(int i = 0; i < arr.length / 2; i++)
        {
            byte temp = arr[i];
            arr[i] = arr[arr.length - i - 1];
            arr[arr.length - i - 1] = temp;
        }
    }
    
    static class IncorrectSignException extends Exception  {
        public IncorrectSignException(String message) {
            super(message);
        }
    }

    public static void signingFile(String filename, String privateKey) throws IOException, NoSuchAlgorithmException {
        File f = new File(filename);
        File k = new File(privateKey);

        PrivateKey key = RSA.getPrivateKey(privateKey);
        long sizeOfFile = RSA.getSizeOfFile(filename);
        byte[] sourceSHA = RSA.getFileSHA256(f, sizeOfFile);
        BigInteger[] cryptedSHA = RSA.crypt(key.d, key.N, sourceSHA);



        String personalSign = "ozzero"; // Сигнатурная подпись
        try (FileOutputStream out = new FileOutputStream(f, true)) {
            out.write(personalSign.getBytes());                             // Метка в начало
            
            ByteBuffer size = ByteBuffer.allocate(8).putLong(sizeOfFile);
            out.write(size.array());                                        // Записываем исходный размер файла

            for(int i = 0; i < 32; i++) {
                ByteBuffer bb = ByteBuffer.allocate(258);                   // Создаем буффер на 258 байт
                byte[] inverted = cryptedSHA[i].toByteArray().clone();
                invertArray(inverted);
                bb.put(inverted);                                        // Записываем в буффер один байт хеш-суммы
                out.write(bb.array());                                      // Записываем в файл
            }
            out.write(personalSign.getBytes());                             // Метка в конец
        }
        catch (Exception e) {
            e.printStackTrace();
        }

    }


    public static void chechSign(String filename, String publicKey) throws IOException, NoSuchAlgorithmException {
        File f = new File(filename);
        File k = new File(publicKey);

        PublicKey key = RSA.getPublicKey(publicKey);
        long content = RSA.getSizeOfFile(filename) - 8276;                  // Размер файла до подписи

        byte[] sourceSHA = RSA.getFileSHA256(f, content);                   // Исходный SHA256

        BigInteger[] cryptedSHA = new BigInteger[32];                       // Распакованный SHA256
        try (FileInputStream in = new FileInputStream(f)) {
            in.skip(content);
            
            String personalSign = new String(in.readNBytes("ozzero".getBytes().length));     // Считываем 6 байт и ищем тег "ozzero"
            if (!personalSign.equals("ozzero")) {
                throw new IncorrectSignException("Failed to find signing");
            }

            ByteBuffer size = ByteBuffer.allocate(8);               // Проверяем размерность файла с тем что записано в подписи
            size.put(in.readNBytes(8)).position(0);
            if (size.getLong() != content) {
                throw new IncorrectSignException("File size mismatch detected");
            }

            for(int i = 0; i < 32; i++) {
                ByteBuffer bb = ByteBuffer.allocate(258);
                bb.put(in.readNBytes(258));
                byte[] inverted = bb.array();
                invertArray(inverted);
                cryptedSHA[i] = new BigInteger(inverted);
            }

            byte[] decryptedSHA = RSA.decrypt(key.e, key.N, cryptedSHA);

            if (!Arrays.equals(sourceSHA, decryptedSHA)) {
                throw new IncorrectSignException("Hash sum is not equals");
            }

            personalSign = new String(in.readNBytes("ozzero".getBytes().length));     // Считываем 6 байт и ищем тег "ozzero"
            if (!personalSign.equals("ozzero")) {
                throw new IncorrectSignException("Failed to find end of sign");
            }

            if (in.available() != 0) {
                throw new IncorrectSignException("After sign had unexpected content");
            }

            System.out.println("Sign is verified");

        }
        catch (IncorrectSignException e) {
            System.out.println(e.getMessage());
        }
        catch (Exception e) {
            e.printStackTrace();
        }
        
    }

    
}
