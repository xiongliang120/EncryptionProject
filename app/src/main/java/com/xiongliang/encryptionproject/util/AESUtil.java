package com.xiongliang.encryptionproject.util;

import android.util.Base64;

import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class AESUtil {

    /**
     * 秘钥长度
     */
    private static final int SECURE_KEY_LENGTH = 16;

    private static final String IV_STRING = "16-Bytes--String";




    /**
     * AES加密字符串
     *
     * @param content
     *            需要被加密的字符串
     * @param secureKey
     *            加密需要的密码
     * @return 密文
     */
    public static byte[] encrypt(String content, String secureKey) {
        if (content == null) {
            return null;
        }
        try {
            // 获得密匙数据
            byte[] rawKeyData = getAESKey(secureKey);
            // 从原始密匙数据创建KeySpec对象
            SecretKeySpec key = new SecretKeySpec(rawKeyData, "AES");
            // Cipher对象实际完成加密操作
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            // 用密匙初始化Cipher对象
            byte[] initParam = IV_STRING.getBytes();
            IvParameterSpec ivParameterSpec = new IvParameterSpec(initParam);
            cipher.init(Cipher.ENCRYPT_MODE, key, ivParameterSpec);
            // 正式执行加密操作

            byte[] encryptByte = cipher.doFinal(content.getBytes());

            return  encryptByte;

        }catch (UnsupportedEncodingException e){
             e.printStackTrace();
        }catch (NoSuchAlgorithmException e){
             e.printStackTrace();
        }catch (NoSuchPaddingException e){
             e.printStackTrace();
        }catch (InvalidAlgorithmParameterException e){
             e.printStackTrace();
        }catch (InvalidKeyException e){
             e.printStackTrace();
        }catch (IllegalBlockSizeException e){
             e.printStackTrace();
        }catch (BadPaddingException e){
             e.printStackTrace();
        }
        return null;

    }


    public static byte[] getAESKey(String key)
            throws UnsupportedEncodingException {
        byte[] keyBytes;
        keyBytes = key.getBytes("UTF-8");
        byte[] keyBytes16 = new byte[SECURE_KEY_LENGTH];
        System.arraycopy(keyBytes, 0, keyBytes16, 0,
                Math.min(keyBytes.length, SECURE_KEY_LENGTH));
        return keyBytes16;
    }


    /**
     * 解密AES加密过的字符串
     *
     * @param content
     *            AES加密过过的内容
     * @param secureKey
     *            加密时的密码
     * @return 明文
     */
    public static String decrypt(byte[] content, String secureKey) {
        if (content == null) {
            return null;
        }

        try {
            // 获得密匙数据
            byte[] rawKeyData = getAESKey(secureKey); // secureKey.getBytes();
            // 从原始密匙数据创建一个KeySpec对象
            SecretKeySpec key = new SecretKeySpec(rawKeyData, "AES");
            // Cipher对象实际完成解密操作
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            // 用密匙初始化Cipher对象
            byte[] initParam = IV_STRING.getBytes();
            IvParameterSpec ivParameterSpec = new IvParameterSpec(initParam);
            cipher.init(Cipher.DECRYPT_MODE, key, ivParameterSpec);
            return  new String(cipher.doFinal(content),"UTF-8");
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        }

        return null;
    }

}
