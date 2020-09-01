package com.melot.magic;

/**
 * Created by siwen.hu on 2020/4/3.
 */
public class Magic {
    public static native String enp(String str);

    public static native String em5(String str, String strup);

    public static native String em5byte(byte[] strByte, String strup);


    public static native String test();

    /**
     * 服务端 新Http的加密方式,KK独用
     *
     * @param data 待签名串
     * @return 签名后数据
     */
    public static native String fire(String data);


    /**
     * @param data 待签名串
     * @param key  签名Key。KK分配
     * @return 签名后数据
     */
    public static native String sign(String data, String key);
}
