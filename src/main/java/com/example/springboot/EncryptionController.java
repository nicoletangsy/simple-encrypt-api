package com.example.springboot;

import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.context.annotation.Configuration;

import javax.crypto.spec.IvParameterSpec;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

import com.example.springboot.encryption.Encrypt;

@RestController
@RequestMapping(path = "/aes")
public class EncryptionController {

    Encrypt encrypt = new Encrypt();
    IvParameterSpec ivParameterSpec = encrypt.generateIv();

    @RequestMapping(value = "/encrypt", method = RequestMethod.POST,
            produces = "application/json")
    @ResponseBody
    public Map encrypt(@RequestParam(value = "plain_text", required=true) String plainText,
                       @RequestParam(value = "aes_key", required=true) String aesKey,
                       @RequestParam(value = "cipher_mode", required=false, defaultValue="ECB") String mode,
                       @RequestParam(value = "key_length", required=false, defaultValue="256") int length,
                       @RequestParam(value = "iv", required=false, defaultValue="") String iv,
                       @RequestParam(value = "format", required=false, defaultValue="HEX") String format) {
        Map res = new HashMap<String, String>();
        try {
            String encrypted = encrypt.encrypt("AES/ECB/PKCS5Padding", plainText, aesKey, ivParameterSpec);
            res.put("cipher_text", encrypted);
            return res;
        } catch (Exception e) {
            System.out.println(e);
            res.put("error", e.toString());
            return res;
        }
    }

    @RequestMapping(value = "/decrypt", method = RequestMethod.POST,
            produces = "application/json")
    public Map decrypt(@RequestParam(value = "cipher_text", required=true) String cipherText ,
                          @RequestParam(value = "aes_key", required=true) String aesKey,
                          @RequestParam(value = "cipher_mode", required=false, defaultValue="ECB") String mode,
                          @RequestParam(value = "key_length", required=false, defaultValue="256") int length,
                          @RequestParam(value = "iv", required=false, defaultValue="") String iv,
                          @RequestParam(value = "format", required=false, defaultValue="HEX") String format) {
        Map res = new HashMap<String, String>();
        try {
            String decrypted = encrypt.decrypt("AES/ECB/PKCS5Padding", cipherText, aesKey, ivParameterSpec);
            String base64res = encrypt.toBase64(decrypted);
            res.put("plain_text", decrypted);
            res.put("base64", base64res);
            return res;
        } catch (Exception e) {
            System.out.println(e);
            res.put("error", e.toString());
            return res;
        }
    }

}
