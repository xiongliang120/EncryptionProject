package com.xiongliang.encryptionproject.util;

import android.util.Base64;
import android.util.Log;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;

/**
 * 使用Android 自带Base64加解密会报错
 */

public class Base64Util {

    public static String encode(byte[] data) {
        return  Base64.encodeToString(data,Base64.NO_WRAP);
    }


    public static byte[] decode(String content) {
        return Base64.decode(content,Base64.NO_WRAP);
    }

}
