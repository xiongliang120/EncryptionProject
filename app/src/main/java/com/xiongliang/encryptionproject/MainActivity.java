package com.xiongliang.encryptionproject;

import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.util.Log;
import android.view.View;
import android.widget.Button;

import com.xiongliang.encryptionproject.util.AESUtil;
import com.xiongliang.encryptionproject.util.Base64Util;
import com.xiongliang.encryptionproject.util.DesUtil;
import com.xiongliang.encryptionproject.util.ParseSystemUtil;
import com.xiongliang.encryptionproject.util.RSAUtil;

import java.security.KeyPair;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

public class MainActivity extends AppCompatActivity {
    private Button aesBaseButton;
    private Button aesHexButton;
    private Button rsaButton;
    private Button rsaSectionButton;
    private Button desButton;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        aesBaseButton = findViewById(R.id.aesBaseButton);
        aesHexButton = findViewById(R.id.aesHexButton);
        rsaButton = findViewById(R.id.rsaButton);
        rsaSectionButton = findViewById(R.id.rsaSectionButton);
        desButton = findViewById(R.id.desButton);


        aesBaseButton.setOnClickListener(onClickListener);
        aesHexButton.setOnClickListener(onClickListener);
        rsaButton.setOnClickListener(onClickListener);
        rsaSectionButton.setOnClickListener(onClickListener);
        desButton.setOnClickListener(onClickListener);
    }


    View.OnClickListener onClickListener = new View.OnClickListener() {
        @Override
        public void onClick(View view) {
            int id = view.getId();
            switch (id) {
                case R.id.aesBaseButton:
                    testAesAndBase64();
                    break;
                case R.id.aesHexButton:
                    testAesAndHex();
                    break;
                case R.id.rsaButton:
                    testRsa();
                    break;
                case R.id.rsaSectionButton:
                    testRsaSection();
                    break;
                case R.id.desButton:
                    testDes();
                    break;
                default:
                    break;
            }
        }
    };


    public void testAesAndBase64() {
        try {
            //加密
            String text = "用AES对称加密加密数据";
            String password = "123456789ABCDEFG";
            byte[] aesData = AESUtil.encrypt(text, password);
            String aesBase64Data = Base64Util.encode(aesData);
            Log.i("msg", "aes加密后转base64为" + aesBase64Data);

            //解密
            aesData = Base64Util.decode(aesBase64Data);
            text = AESUtil.decrypt(aesData, password);
            Log.i("msg", "解密后字符串为" + text);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }


    public void testAesAndHex() {
        try {
            //加密
            String text = "用AES对称加密加密数据";
            String password = "123456789ABCDEFG";
            byte[] aesData = AESUtil.encrypt(text, password);
            String aesBase64Data = ParseSystemUtil.parseByte2HexStr(aesData);
            Log.i("msg", "aes加密后转base64为" + aesBase64Data);

            //解密
            aesData = ParseSystemUtil.parseHexStr2Byte(aesBase64Data);
            text = AESUtil.decrypt(aesData, password);
            Log.i("msg", "解密后字符串为" + text);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    /**
     * 使用公钥加密，私钥解密
     */
    public void testRsa() {
        try {
            String text = "Abcd";
            //第一步,生成秘钥对
            KeyPair keyPair = RSAUtil.generateRSAKeyPair(RSAUtil.DEFAULT_KEY_SIZE);
            // 公钥
            RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
            // 私钥
            RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();

            //第二步,使用公钥加密
            byte[] encryptBytes = RSAUtil.encryptByPublicKey(text.getBytes(), publicKey.getEncoded());
            String encryStr = Base64Util.encode(encryptBytes);
            Log.i("msg", "打印RSA 公钥解密后数据=" + encryStr);

            //第三步,使用私钥解密
            byte[] decryptBytes = RSAUtil.decryptByPrivateKey(Base64Util.decode(encryStr), privateKey.getEncoded());
            String decryStr = new String(decryptBytes);
            Log.i("msg", "打印RSA 私钥解密后数据=" + decryStr);
        } catch (Exception e) {
            e.printStackTrace();
        }

    }

    /**
     * 使用RSA 实现分段加密
     */
    public void testRsaSection() {
        try {
            String text = "使用RSA 公钥进行加密, 使用私钥进行解密，测试看下数据如果过长的话，是否会报错，在报错的情况下就要实现加密数据的分段加密" +
                    "使用RSA 公钥进行加密, 使用私钥进行解密，测试看下数据如果过长的话，是否会报错，在报错的情况下就要实现加密数据的分段加密" +
                    "使用RSA 公钥进行加密, 使用私钥进行解密，测试看下数据如果过长的话，是否会报错，在报错的情况下就要实现加密数据的分段加密" +
                    "使用RSA 公钥进行加密, 使用私钥进行解密，测试看下数据如果过长的话，是否会报错，在报错的情况下就要实现加密数据的分段加密" +
                    "使用RSA 公钥进行加密, 使用私钥进行解密，测试看下数据如果过长的话，是否会报错，在报错的情况下就要实现加密数据的分段加密";
            //第一步,生成秘钥对
            KeyPair keyPair = RSAUtil.generateRSAKeyPair(RSAUtil.DEFAULT_KEY_SIZE);
            // 公钥
            RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
            // 私钥
            RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();

            //第二步,使用公钥加密
            byte[] encryptBytes = RSAUtil.encryptByPublicKeyForSpilt(text.getBytes(), publicKey.getEncoded());
            String encryStr = Base64Util.encode(encryptBytes);
            Log.i("msg", "打印RSA 公钥解密后数据=" + encryStr);

            //第三步,使用私钥解密
            byte[] decryptBytes = RSAUtil.decryptByPrivateKeyForSpilt(Base64Util.decode(encryStr), privateKey.getEncoded());
            String decryStr = new String(decryptBytes);
            Log.i("msg", "打印RSA 私钥解密后数据=" + decryStr);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }


    public void testDes(){
        String  text = "测试使用Dex 进行加密解密";
        String key = DesUtil.generateKey();
        String desData = DesUtil.encode(key,text.getBytes());
        Log.i("msg","des 加密后的数据="+desData);
        String data = DesUtil.decode(key,Base64Util.decode(desData));
        Log.i("msg","des 解密后的数据="+data);
    }

}
