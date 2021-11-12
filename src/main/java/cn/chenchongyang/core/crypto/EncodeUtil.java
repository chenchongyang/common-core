package cn.chenchongyang.core.crypto;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Hex;

import java.nio.charset.StandardCharsets;

/**
 * 编码转换工具
 *
 * @author 陈崇洋
 * @since 2021-02-05
 */
public final class EncodeUtil {

    private EncodeUtil() {
    }

    public static String toHex(byte[] bytes) {
        return Hex.encodeHexString(bytes, false);
    }

    public static String toBase64(byte[] bytes) {
        return Base64.encodeBase64String(bytes);
    }

    public static byte[] stringToByte(String str) {
        return str.getBytes(StandardCharsets.UTF_8);
    }

    public static byte[] base64ToByte(String str) {
        return Base64.decodeBase64(str);
    }

    public static String toString(byte[] bytes) {
        return new String(bytes, StandardCharsets.UTF_8);
    }
}