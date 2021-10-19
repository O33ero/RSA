package com.mirea;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.util.Random;

import com.mirea.RSA.KeyPair.PrivateKey;
import com.mirea.RSA.KeyPair.PublicKey;

public class RSA {
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
     * 
     * 
     */

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


    public static BigInteger getInverse(BigInteger V, BigInteger M) { 

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

        int i = new Random().nextInt(24 - 5) + 5;                      // Случайное целое число из диопазона(5, 24)
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


    public static BigInteger[] crypt(BigInteger e, BigInteger N, BigInteger[] source) {
        BigInteger[] result = new BigInteger[source.length];

        for(int i = 0; i < source.length; i++) {
            BigInteger m = source[i];
            BigInteger c = m.modPow(e, N);
            result[i] = c.signum() < 0 ? c.add(N) : c;
        }

        return result;
    }

    public static BigInteger[] decrypt(BigInteger d, BigInteger N, BigInteger[] source) {
        BigInteger[] result = new BigInteger[source.length];

        for(int i = 0; i < source.length; i++) {
            BigInteger m = source[i];
            BigInteger c = m.modPow(d, N);
            result[i] = c.signum() < 0 ? c.add(N) : c;
        }

        return result;
    }
}
