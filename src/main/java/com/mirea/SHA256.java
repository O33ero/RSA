package com.mirea;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;

public class SHA256 {

    

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
     * Переводит из массива байтов в массив битов
     * @param bitContainer - массив битов, в который будет сделана запись
     * @param source - источник байтов
     * @return Последний пустой элемент
     */
    private static int convertToBits(byte[] bitContainer, byte[] source) {
        for(int i = 0; i < source.length * 8; i++) {
            byte nowByte = source[i / 8];

            bitContainer[i] = (byte)(nowByte >> (7 - (i % 8)) & 1);
        }

        return source.length * 8;
    } 


    /**
     * Запись размера контента в послднии 64 байта {@code bitConteiner} 
     * @param bitContainer - массив битов
     * @param contentSize - размер контента
     */
    private static void writeContentSize(byte[] bitContainer, long contentSize) {
        int rnd = 63;
        for(int i = bitContainer.length - 64; i < bitContainer.length; i++) {
            bitContainer[i] = (byte)(contentSize >> rnd & 1);
            rnd--;
        }
    }


    /**
     * Запись из массива битов {@code bitContainer} в массив слов (слово = 32 байта) {@code words}. 
     * @param bitContainer - массив битов
     * @param words - массив слов
     * @param count - количество слов, которые надо скопировать
     */
    private static void writeWords(byte[] bitContainer, int[] words, int count) {
        int j = count - 1;   // Счетчит слов
        int rnd = 0;
        int temp = 0;
        for(int i = count * 32 - 1; i >= 0 ; i--) {

            if(bitContainer[i] == 1) {
                temp |= 1 << rnd; // Устанавливает rnd бит в 1
            }
            rnd++;
            
            if (i % 32 == 0) {
                words[j] = temp;
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
            src = src >> 1;
            if (bit == 1) // https://stackoverflow.com/questions/4674006/set-specific-bit-in-byte
                src |= 1 << 31;
            else
                src &= ~(1 << 31);

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

            src &= ~(1 << 31);// https://stackoverflow.com/questions/4674006/set-specific-bit-in-byte

            result = src;
        }

        return result;
    }

    /**
     * Переводит массив слов в байты
     * @param source - исходный массив слов
     * @return Массив байт
     */
    public static byte[] convertToBytes(int[] source) {
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
     */
    public static String bytesToHex(byte[] bytes) { // https://stackoverflow.com/questions/9655181/how-to-convert-a-byte-array-to-a-hex-string-in-java
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
     */
    public static byte[] getHash(byte[] content) { // https://tproger.ru/translations/sha-2-step-by-step/

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
        int bitContainerSize = content.length * 8 ;                             // Чисто контент
        bitContainerSize += 1;                                                  // 1 бит равный единице
        bitContainerSize = bitContainerSize + (512 - bitContainerSize % 512);   // Выравниваем до 512; 
        

        /**
         * Предворительное заполнение
         */
        byte[] bitContainer = new byte[bitContainerSize];                       // Инициализация массива бит
        int lastIndex = convertToBits(bitContainer, content);                   // Чисто контент
        bitContainer[lastIndex] = 1;                                            // Приколюхная единичка
        long contentSize = content.length * 8;                                  // Размер контента
        writeContentSize(bitContainer, contentSize);



        /**
         * Основной цикл хеширования
         */
        int[] hArr = new int [8];

        for(int i = 0; i < bitContainerSize / 512; i++) { 
            byte[] subBitContainer = new byte[512];
            System.arraycopy(bitContainer, i * 512, subBitContainer, 0, 512);   // Для каждого 512-битного куска

            int[] words = new int[64];                                          // Добавляем слов до 64, инициализированных нулями, 
            writeWords(subBitContainer, words, 16); 

            for(int j = 16; j < 64; j++) {
                int a = roundRotateRight(words[j - 15], 7);
                int b = roundRotateRight(words[j - 15], 18);
                int c = shiftRotateRight(words[j - 15], 3);

                int s0 = a ^ b ^ c;

                a = roundRotateRight(words[j - 2], 17);
                b = roundRotateRight(words[j - 2], 19);
                c = shiftRotateRight(words[j - 2], 10);

                int s1 = a ^ b ^ c;

                a = words[j - 16];
                b = words[j - 7];
                words[j] = words[j - 16] + s0 + words[j - 7] + s1;
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
                int temp1 = h + S1 + ch + k[j] + words[j];
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
