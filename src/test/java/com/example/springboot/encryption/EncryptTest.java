package com.example.springboot.encryption;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

public class EncryptTest {

    @Test
    void encryptECBSuccess()
            throws NoSuchAlgorithmException, IllegalBlockSizeException, InvalidKeyException,
            BadPaddingException, InvalidAlgorithmParameterException, NoSuchPaddingException {
        // given
        String input = "Apple";
        String sKey = "404D635166546A576E5A723475377721";
        String algorithm = "AES/ECB/PKCS5Padding";
        IvParameterSpec ivParameterSpec = Encrypt.generateIv();

        // when
        String cipherText = Encrypt.encrypt(algorithm, input, sKey, ivParameterSpec);

        // then
        String res = "C9E461E80EC3047944ACAE96A9896BC3";
        Assertions.assertEquals(cipherText, res);
    }

    @Test
    void decryptECBSuccess()
            throws NoSuchAlgorithmException, IllegalBlockSizeException, InvalidKeyException,
            BadPaddingException, InvalidAlgorithmParameterException, NoSuchPaddingException {
        // given
        String cipherText = "C9E461E80EC3047944ACAE96A9896BC3";
        String sKey = "404D635166546A576E5A723475377721";
        String algorithm = "AES/ECB/PKCS5Padding";
        IvParameterSpec ivParameterSpec = Encrypt.generateIv();

        // when
        String res = "Apple";
        String plainText = Encrypt.decrypt(algorithm, cipherText, sKey, ivParameterSpec);

        // then
        Assertions.assertEquals(res, plainText);
    }

    @Test
    void toBase64Success()
            throws NoSuchAlgorithmException, IllegalBlockSizeException, InvalidKeyException,
            BadPaddingException, InvalidAlgorithmParameterException, NoSuchPaddingException {
        // given
        String input = "Apple";

        // when
        String base64 = Encrypt.toBase64(input);

        // then
        String res = "QXBwbGU=";
        Assertions.assertEquals(res, base64);
    }

    @Test
    void encryptECBbyRandomKeySuccess()
            throws NoSuchAlgorithmException, IllegalBlockSizeException, InvalidKeyException,
            BadPaddingException, InvalidAlgorithmParameterException, NoSuchPaddingException {
        // given
        String input = "Apple";
        SecretKey key = Encrypt.generateKey(128);
        // get base64 encoded version of the key
        String sKey = Base64.getEncoder().encodeToString(key.getEncoded());
        String algorithm = "AES/ECB/PKCS5Padding";
        IvParameterSpec ivParameterSpec = Encrypt.generateIv();

        // when
        String cipherText = Encrypt.encrypt(algorithm, input, sKey, ivParameterSpec);
        String plainText = Encrypt.decrypt(algorithm, cipherText, sKey, ivParameterSpec);

        // then
        Assertions.assertEquals(input, plainText);
    }
}
