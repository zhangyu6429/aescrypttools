
package com.zhy.aestools;

import android.content.Context;
import android.content.SharedPreferences;
import android.text.TextUtils;
import android.util.Base64;

import java.nio.charset.Charset;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * AES加密工具， Android9.0可正常使用
 */
public class AESCryptTools {

    /**
     * 生成MD5字符串使用
     */
    private static char[] HEXTABLE = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};


    private Context mContext;

    /**
     * 用于存储salt byte数据
     */
    private String mAesSharedPreferencesFileName;

    /**
     * 秘钥
     */
    private byte[] mSecretKeyBytes;

    private AESCryptTools(Context context, String password, String aesSharedPreferencesFileName)
            throws NoSuchAlgorithmException, InvalidKeySpecException, RuntimeException {

        mContext = context;
        mAesSharedPreferencesFileName = aesSharedPreferencesFileName;

        if (TextUtils.isEmpty(password)) {
            throw new RuntimeException("password is invalid!");
        }

        if (TextUtils.isEmpty(mAesSharedPreferencesFileName)) {
            throw new RuntimeException("aesSharedPreferencesFileName is invalid!");
        }

        mSecretKeyBytes = getSecretKeyBytes(password);

        if (mSecretKeyBytes == null) {
            throw new RuntimeException("secret key create failed!");
        }
    }

    /**
     * 加密字符串
     *
     * @param cleartext
     * @return
     */
    public String encrypt(String cleartext) {
        if (TextUtils.isEmpty(cleartext)) {
            return cleartext;
        }

        try {
            byte[] result = encrypt(cleartext.getBytes(Charset.forName("UTF-8")));
            return encodeBase64(result);
        } catch (Exception e) {
            e.printStackTrace();
        }

        return null;
    }


    /**
     * 解密字符串
     *
     * @param encryptStr
     * @return
     */
    public String decrypt(String encryptStr) {
        if (TextUtils.isEmpty(encryptStr)) {
            return encryptStr;
        }

        try {
            byte[] enc = decodeBase64ToBytes(encryptStr);
            byte[] result = decrypt(enc);
            return new String(result, Charset.forName("UTF-8"));
        } catch (Exception e) {
            e.printStackTrace();
        }

        return null;
    }


    /**
     * 解密byte数组
     *
     * @param encrypted
     * @return
     * @throws Exception
     */
    public byte[] decrypt(byte[] encrypted) {
        byte[] decrypted = null;

        try {
            SecretKeySpec skeySpec = new SecretKeySpec(mSecretKeyBytes, "AES");
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, skeySpec, new IvParameterSpec(new byte[cipher.getBlockSize()]));
            decrypted = cipher.doFinal(encrypted);
        } catch (Exception e) {
            e.printStackTrace();
        }

        return decrypted;
    }


    /**
     * 加密byte数组
     *
     * @param clear
     * @return
     * @throws Exception
     */
    public byte[] encrypt(byte[] clear) {
        byte[] encrypted = null;

        try {
            SecretKeySpec skeySpec = new SecretKeySpec(mSecretKeyBytes, "AES");
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, skeySpec, new IvParameterSpec(new byte[cipher.getBlockSize()]));
            encrypted = cipher.doFinal(clear);
        } catch (Exception e) {
            e.printStackTrace();
        }

        return encrypted;
    }


    /**
     * 生成秘钥
     *
     * @param password
     * @return
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException
     */
    private byte[] getSecretKeyBytes(String password) throws NoSuchAlgorithmException, InvalidKeySpecException {

        int saltLen = 64;
        int keyLen = 256;
        int iterationCount = 20;

        byte[] salt = null;

        SharedPreferences sp = mContext.getSharedPreferences(mAesSharedPreferencesFileName, Context.MODE_PRIVATE);
        String saltSpKey = "salt_" + getMD5(encodeBase64(password.getBytes()).getBytes());

        String saltStr = sp.getString(saltSpKey, "");
        if (!TextUtils.isEmpty(saltStr)) {
            salt = decodeBase64ToBytes(saltStr);
        }

        if (salt == null || salt.length != saltLen) {
            salt = new byte[saltLen];
            SecureRandom random = new SecureRandom();
            random.nextBytes(salt);
            sp.edit().putString(saltSpKey, encodeBase64(salt));
        }

        KeySpec keySpec = new PBEKeySpec(password.toCharArray(), salt, iterationCount, keyLen);
        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
        byte[] keyBytes = keyFactory.generateSecret(keySpec).getEncoded();

        return keyBytes;
    }


    /**
     * 将byte数组转换成Base64编码的字符串
     *
     * @param source
     * @return base64编码的字符串
     */
    private static String encodeBase64(byte[] source) {
        if (source != null && source.length > 0) {
            byte[] data = Base64.encode(source, Base64.NO_WRAP);
            if (data != null && data.length > 0) {
                return new String(data, Charset.forName("US-ASCII"));
            }
        }
        return null;
    }


    /**
     * 将String转换成Base64编码的byte数组
     *
     * @param base64Str
     * @return base64编码的字符串
     */
    private static byte[] decodeBase64ToBytes(String base64Str) {
        if (!TextUtils.isEmpty(base64Str)) {
            return Base64.decode(base64Str.getBytes(Charset.forName("US-ASCII")), Base64.NO_WRAP);
        }
        return null;
    }


    /**
     * 获取字符串MD5值
     *
     * @param bytes
     * @return
     */
    private String getMD5(byte[] bytes) {
        String md5Str = "";
        try {
            MessageDigest m = MessageDigest.getInstance("MD5");
            m.update(bytes, 0, bytes.length);

            byte[] array = m.digest();

            for (int i = 0; i < array.length; ++i) {
                int di = (array[i] + 256) & 0xFF; // Make it unsigned
                md5Str = md5Str + HEXTABLE[(di >> 4) & 0xF] + HEXTABLE[di & 0xF];
            }
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }

        return md5Str;
    }
}
