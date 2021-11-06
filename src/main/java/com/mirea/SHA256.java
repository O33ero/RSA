package com.mirea;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.InvalidParameterException;

public class SHA256 {

    
    /**
     * Константы
     */
    private static int[] k = {
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2 
    };

    /**
     * Устанавливает {@code c}-ый бит числа {@code t} в значение {@code v}
     * @param t - число
     * @param c - номер бита
     * @param v - значение бита
     * @return Число с изменненым битом
     * 
     * @see https://stackoverflow.com/questions/4674006/set-specific-bit-in-byte
     */
    private static int setBit(int t, int c, int v) { 
        if (v != 1 && v != 0) 
            throw new InvalidParameterException("New value of bit should be 0 or 1");

        if (v == 1) 
            t |= 1 << c;
        else 
            t &= ~(1 << c);

        return t;
    }

    /**
     * Переводит из массива байтов в массив битов
     * @param bitArray - массив битов, в который будет сделана запись
     * @param source - источник байтов
     * @return Последний пустой элемент
     */
    private static int convertToBits(byte[] bitArray, byte[] source) {
        for(int i = 0; i < source.length * 8; i++) {
            byte nowByte = source[i / 8];

            bitArray[i] = (byte)(nowByte >> (7 - (i % 8)) & 1);
        }

        return source.length * 8;
    } 


    /**
     * Запись размера контента в послднии 64 байта {@code bitArray} 
     * @param bitArray - массив битов
     * @param contentSize - размер контента
     */
    private static void writeContentSize(byte[] bitArray, long contentSize) {
        int rnd = 63;
        for(int i = bitArray.length - 64; i < bitArray.length; i++) {
            bitArray[i] = (byte)(contentSize >> rnd & 1);
            rnd--;
        }
    }


    /**
     * Запись из массива битов {@code bitArray} в массив слов (слово = 32 бита) {@code w}. 
     * @param bitArray - массив битов
     * @param w - массив слов
     * @param count - количество слов, которые надо скопировать
     */
    private static void writeWords(byte[] bitArray, int[] w, int count) {
        int j = count - 1;
        int rnd = 0;
        int temp = 0;
        for(int i = count * 32 - 1; i >= 0 ; i--) {

            if(bitArray[i] == 1) {
                temp = setBit(temp, rnd, 1);
            }
            rnd++;
            
            if (i % 32 == 0) {
                w[j] = temp;
                j--;
                temp = 0;
                rnd = 0;
            }
        }
    }
    

    

    /**
     * Круговой сдвиг вправо
     * @param src - исходное число
     * @param count - длина сдвига
     * @return Результирующее число
     */
    private static int roundRotateRight(int src, int count) {
        int result = src;
        for(int i = 0; i < count; i++) {
            int bit = src & 1; // Последний бит
            src = src >>> 1;
            if (bit == 1) 
                src = setBit(src, 31, 1);   
            else
                src = setBit(src, 31, 0);

            result = src;

        }
        return result;
    }

    /**
     * Битовый сдвиг вправо
     * @param src - исходное число
     * @param count - длина сдвига
     * @return Получившиеся число
     */
    private static int shiftRotateRight(int src, int count) {
        int result = src;
        for(int i = 0; i < count; i++) {
            src = src >> 1;

            src = setBit(src, 31, 0);

            result = src;
        }

        return result;

        // return src >>> count;
    }

    /**
     * Переводит массив слов в байты
     * @param source - исходный массив слов
     * @return Массив байт
     */
    private static byte[] convertToBytes(int[] source) {
        byte[] result = new byte[source.length * 4];
        int index = 0;

        for(int i = 0; i < source.length; i++) {
            ByteBuffer bb = ByteBuffer.allocate(4);
            bb.putInt(source[i]);

            System.arraycopy(bb.array(), 0, result, index, 4);
            index += 4;
        }
        return result;
    }

    /**
     * Превращает массив байтов в 16-ричною строку
     * @param bytes - массив байт
     * @return Строка в 16-ричном виде
     * @see https://stackoverflow.com/questions/9655181/how-to-convert-a-byte-array-to-a-hex-string-in-java
     */
    public static String bytesToHex(byte[] bytes) {
        byte[] HEX_ARRAY = "0123456789abcdef".getBytes(StandardCharsets.US_ASCII);
        byte[] hexChars = new byte[bytes.length * 2];
        for (int j = 0; j < bytes.length; j++) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = HEX_ARRAY[v >>> 4];
            hexChars[j * 2 + 1] = HEX_ARRAY[v & 0x0F];
        }
        return new String(hexChars, StandardCharsets.UTF_8);
    }

    /**
     * Высчитываем хеш-сумму по алгоритму {@code SHA-256} для массива битов {@code content}
     * @param content - массив битов
     * @return Хеш-сумма
     * @see https://tproger.ru/translations/sha-2-step-by-step/
     */
    public static byte[] getHash(byte[] content) {

        /**
         * Начальные параметры
         */
        int h0 = 0x6a09e667;
        int h1 = 0xbb67ae85; 
        int h2 = 0x3c6ef372; 
        int h3 = 0xa54ff53a; 
        int h4 = 0x510e527f; 
        int h5 = 0x9b05688c; 
        int h6 = 0x1f83d9ab; 
        int h7 = 0x5be0cd19; 

        /**
         * Считаем размер
         */
        int bitArraySize = content.length * 8 ;                             // Чисто контент
        bitArraySize += 1;                                                  // 1 бит равный единице
        bitArraySize += 64;                                                 // Оставляем место под размер содержимого
        bitArraySize = bitArraySize + (512 - bitArraySize % 512);           // Выравниваем до 512; 
        

        /**
         * Предворительное заполнение
         */
        byte[] bitArray = new byte[bitArraySize];                           // Инициализация массива бит
        int lastIndex = convertToBits(bitArray, content);                   // Чисто контент
        bitArray[lastIndex] = 1;                                            // Приколюхная единичка
        long contentSize = content.length * 8;                              // Размер контента
        writeContentSize(bitArray, contentSize);



        /**
         * Основной цикл хеширования
         */

        for(int i = 0; i < bitArraySize / 512; i++) { 
            byte[] subBitArray = new byte[512];                             // Берем кусок битового массива длиной 512 бит
            System.arraycopy(bitArray, i * 512, subBitArray, 0, 512);       

            int[] w = new int[64];                                          // Добавляем 48 32-битных слов, заполненые нулями 
            writeWords(subBitArray, w, 16);                                 // Записываем первые 16 слов (512 бит)

            for(int j = 16; j < 64; j++) {
                int a = roundRotateRight(w[j - 15], 7);
                int b = roundRotateRight(w[j - 15], 18);
                int c = shiftRotateRight(w[j - 15], 3);

                int s0 = a ^ b ^ c;

                a = roundRotateRight(w[j - 2], 17);
                b = roundRotateRight(w[j - 2], 19);
                c = shiftRotateRight(w[j - 2], 10);

                int s1 = a ^ b ^ c;

                w[j] = w[j - 16] + s0 + w[j - 7] + s1;
            }

            /**
             * Цикл сжатия
             */
            int a = h0;
            int b = h1;
            int c = h2;
            int d = h3;
            int e = h4;
            int f = h5;
            int g = h6;
            int h = h7;
            for(int j = 0; j < 64; j++) {
                int S1 = roundRotateRight(e, 6) ^ roundRotateRight(e, 11) ^ roundRotateRight(e, 25);
                int ch = (e & f) ^ ((~e) & g);
                int temp1 = h + S1 + ch + k[j] + w[j];
                int S0 = roundRotateRight(a, 2) ^ roundRotateRight(a, 13) ^ roundRotateRight(a, 22);
                int maj = (a & b) ^ (a & c) ^ (b & c);
                int temp2 = S0 + maj;

                h = g;
                g = f;
                f = e;
                e = d + temp1;
                d = c;
                c = b;
                b = a;
                a = temp1 + temp2;
            }

            h0 = h0 + a;
            h1 = h1 + b;
            h2 = h2 + c;
            h3 = h3 + d;
            h4 = h4 + e;
            h5 = h5 + f;
            h6 = h6 + g;
            h7 = h7 + h;
        }

        int[] hArr = new int [8];
        hArr[0] = h0;
        hArr[1] = h1;
        hArr[2] = h2;
        hArr[3] = h3;
        hArr[4] = h4;
        hArr[5] = h5;
        hArr[6] = h6;
        hArr[7] = h7;


        return convertToBytes(hArr);
    }
}
