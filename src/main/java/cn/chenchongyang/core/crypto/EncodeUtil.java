
package cn.chenchongyang.core.crypto;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Hex;

import java.nio.charset.StandardCharsets;

/**
 * 编码转换工具
 * bits -> byte -> hex
 * 128 16 32
 * 256 32 64
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

    public static byte[] base64ToByte(String base64str) {
        return Base64.decodeBase64(base64str);
    }

    public static byte[] hexToByte(String hexStr) {
        try {
            return Hex.decodeHex(hexStr);
        } catch (DecoderException e) {
            throw new IllegalArgumentException("hex decode fail!");
        }
    }

    public static String toString(byte[] bytes) {
        return new String(bytes, StandardCharsets.UTF_8);
    }
}
