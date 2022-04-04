package com.example.springboot.encryption;

import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.BadPaddingException;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKeyFactory;
import javax.crypto.SealedObject;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.Serializable;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

public class Encrypt {

    public Map encrypt(String mode, String input, String aesKey, IvParameterSpec iv) throws
            NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException,
            BadPaddingException, InvalidKeyException {
        Map res = new HashMap<String, String>();

        String algorithm = mode.equals("ECB")
                ? "AES/ECB/PKCS5Padding" : mode;

        // value checking
        boolean isValidAlgo = algorithm.equals("AES/ECB/PKCS5Padding");
        if (!isValidAlgo) {
            res.put("success", "false");
            res.put("reason", "Temporarily only support ECB encryption!");
            return res;
        }

        if (aesKey == null) {
            res.put("success", "false");
            res.put("reason", "Secret Key should not be null");
            return res;
        }

        if (aesKey.length() != 32) {
            res.put("success", "false");
            if (aesKey.length() == 16 || aesKey.length() == 24) {
                res.put("reason", "Temporarily only 256-bit Secret Key");
            } else {
                res.put("reason", "Invalid Secret Key length");
            }
            return res;
        }

        String encrypted = encode(algorithm, input, aesKey, iv);
        res.put("cipher_text", encrypted);
        return res;
    }

    public static String encode(String algorithm, String input, String aesKey, IvParameterSpec iv)
            throws NoSuchPaddingException, NoSuchAlgorithmException,
            InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        byte[] byteKey = aesKey.getBytes();
        SecretKey sKey = new SecretKeySpec(byteKey, 0, byteKey.length, "AES");
        Cipher cipher = Cipher.getInstance(algorithm);
        cipher.init(Cipher.ENCRYPT_MODE, sKey);
        byte[] cipherText = cipher.doFinal(input.getBytes());
        return parseByte2HexStr(cipherText);
    }

    public Map decrypt(String mode, String cipherText, String aesKey, IvParameterSpec iv) throws
            NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException,
            BadPaddingException, InvalidKeyException {
        Map res = new HashMap<String, String>();

        String algorithm = mode.equals("ECB")
                ? "AES/ECB/PKCS5Padding" : mode;

        // value checking
        boolean isValidAlgo = algorithm.equals("AES/ECB/PKCS5Padding");
        if (!isValidAlgo) {
            res.put("success", "false");
            res.put("reason", "Temporarily only support ECB encryption!");
            return res;
        }

        if (aesKey == null) {
            res.put("success", "false");
            res.put("reason", "Secret Key should not be null");
            return res;
        }

        if (aesKey.length() != 32) {
            res.put("success", "false");
            if (aesKey.length() == 16 || aesKey.length() == 24) {
                res.put("reason", "Temporarily only 256-bit Secret Key");
            } else {
                res.put("reason", "Invalid Secret Key length");
            }
            return res;
        }

        String decrypted = decode(algorithm, cipherText, aesKey, iv);
        String base64res = toBase64(decrypted);
        res.put("plain_text", decrypted);
        res.put("base64", base64res);
        return res;
    }

    public static String decode(String algorithm, String cipherText, String aesKey, IvParameterSpec iv)
            throws NoSuchPaddingException, NoSuchAlgorithmException,
            InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        byte[] decryptCipherText = parseHexStr2Byte(cipherText);

        byte[] byteKey = aesKey.getBytes();
        SecretKey sKey = new SecretKeySpec(byteKey, 0, byteKey.length, "AES");
        Cipher cipher = Cipher.getInstance(algorithm);
        cipher.init(Cipher.DECRYPT_MODE, sKey);

        byte[] plainText = cipher.doFinal(decryptCipherText);
        return new String(plainText);
    }

    public static SecretKey generateKey(int n) throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(n);
        SecretKey key = keyGenerator.generateKey();
        return key;
    }

    public static SecretKey getKeyFromPassword(String password, String salt)
            throws NoSuchAlgorithmException, InvalidKeySpecException {
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        KeySpec spec = new PBEKeySpec(password.toCharArray(), salt.getBytes(), 65536, 256);
        SecretKey secret = new SecretKeySpec(factory.generateSecret(spec)
                .getEncoded(), "AES");
        return secret;
    }

    public static IvParameterSpec generateIv() {
        byte[] iv = new byte[16];
        new SecureRandom().nextBytes(iv);
        return new IvParameterSpec(iv);
    }

    public static void encryptFile(String algorithm, SecretKey key, IvParameterSpec iv,
                                   File inputFile, File outputFile) throws IOException, NoSuchPaddingException,
            NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException,
            BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance(algorithm);
        cipher.init(Cipher.ENCRYPT_MODE, key, iv);
        FileInputStream inputStream = new FileInputStream(inputFile);
        FileOutputStream outputStream = new FileOutputStream(outputFile);
        byte[] buffer = new byte[64];
        int bytesRead;
        while ((bytesRead = inputStream.read(buffer)) != -1) {
            byte[] output = cipher.update(buffer, 0, bytesRead);
            if (output != null) {
                outputStream.write(output);
            }
        }
        byte[] outputBytes = cipher.doFinal();
        if (outputBytes != null) {
            outputStream.write(outputBytes);
        }
        inputStream.close();
        outputStream.close();
    }

    public static void decryptFile(String algorithm, SecretKey key, IvParameterSpec iv,
                                   File encryptedFile, File decryptedFile) throws IOException, NoSuchPaddingException,
            NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException,
            BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance(algorithm);
        cipher.init(Cipher.DECRYPT_MODE, key, iv);
        FileInputStream inputStream = new FileInputStream(encryptedFile);
        FileOutputStream outputStream = new FileOutputStream(decryptedFile);
        byte[] buffer = new byte[64];
        int bytesRead;
        while ((bytesRead = inputStream.read(buffer)) != -1) {
            byte[] output = cipher.update(buffer, 0, bytesRead);
            if (output != null) {
                outputStream.write(output);
            }
        }
        byte[] output = cipher.doFinal();
        if (output != null) {
            outputStream.write(output);
        }
        inputStream.close();
        outputStream.close();
    }

    public static SealedObject encryptObject(String algorithm, Serializable object, SecretKey key,
                                             IvParameterSpec iv) throws NoSuchPaddingException, NoSuchAlgorithmException,
            InvalidAlgorithmParameterException, InvalidKeyException, IOException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance(algorithm);
        cipher.init(Cipher.ENCRYPT_MODE, key, iv);
        SealedObject sealedObject = new SealedObject(object, cipher);
        return sealedObject;
    }

    public static Serializable decryptObject(String algorithm, SealedObject sealedObject, SecretKey key,
                                             IvParameterSpec iv) throws NoSuchPaddingException, NoSuchAlgorithmException,
            InvalidAlgorithmParameterException, InvalidKeyException, ClassNotFoundException,
            BadPaddingException, IllegalBlockSizeException, IOException {
        Cipher cipher = Cipher.getInstance(algorithm);
        cipher.init(Cipher.DECRYPT_MODE, key, iv);
        Serializable unsealObject = (Serializable) sealedObject.getObject(cipher);
        return unsealObject;
    }

    public static String encryptPasswordBased(String plainText, SecretKey key, IvParameterSpec iv)
            throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException,
            InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key, iv);
        return Base64.getEncoder()
                .encodeToString(cipher.doFinal(plainText.getBytes()));
    }

    public static String decryptPasswordBased(String cipherText, SecretKey key, IvParameterSpec iv)
            throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException,
            InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
        cipher.init(Cipher.DECRYPT_MODE, key, iv);
        return new String(cipher.doFinal(Base64.getDecoder()
                .decode(cipherText)));
    }

    public static String parseByte2HexStr(byte buf[]) {
        StringBuffer sb = new StringBuffer();
        for (int i = 0; i < buf.length; i++) {
            String hex = Integer.toHexString(buf[i] & 0xFF);
            if (hex.length() == 1) {
                hex = '0' + hex;
            }
            sb.append(hex.toUpperCase());
        }
        return sb.toString();
    }

    public static byte[] parseHexStr2Byte(String hexStr) {
        if (hexStr.length() < 1) {
            return null;
        }
        byte[] res = new byte[hexStr.length()/2];
        for (int i = 0; i < hexStr.length()/2; i++) {
            int high = Integer.parseInt(hexStr.substring(i*2, i*2+1), 16);
            int low = Integer.parseInt(hexStr.substring(i*2+1, i*2+2), 16);
            res[i] = (byte) (high * 16 + low);
        }
        return res;
    }

    public static String toBase64(String decrypted) {
        return Base64.getEncoder().encodeToString(decrypted.getBytes());
    }

}