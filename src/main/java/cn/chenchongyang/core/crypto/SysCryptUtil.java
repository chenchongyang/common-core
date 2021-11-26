
package cn.chenchongyang.core.crypto;

import cn.chenchongyang.core.CommonCoreException;
import cn.chenchongyang.core.util.NumberUtil;

import org.apache.commons.codec.DecoderException;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

/**
 * encrypt-0-0:A9010F5C0779DECF58F8F53E01B5428E:0370FFD89879D22F409EC8DCA0A292E4C8
 * encrypt：标准加密格式头
 * 第一位数字（加密方式）：0:AES加密 1:SM4加密
 * 第二位数字（加密模式）：0:CBC 1:GCM
 */
public final class SysCryptUtil {

    private static byte[] workKey;

    private SysCryptUtil() {
    }

    /**
     * 初始化workKey
     */
    public static void initWorkKeyAndVerifyDigest() {
        byte[] rootKey = RootKeyUtil.getRootKey();
        workKey = RootKeyUtil.getWorkKey0(rootKey);
    }

    /**
     * 使用配置的模式加密
     * 
     * @param rawText 待加密的字符串
     * @return 密文
     */
    public static String encrypt(String rawText) {
        int encryptModel = RootKeyUtil.getEncryptModel();
        switch (encryptModel) {
            // AES_CBC
            case 0:
                return encryptAesCbc(rawText);
            // AES_GCM
            case 1:
            default:
                return encryptAesGcm(rawText);
        }
    }

    /**
     * 解密密文
     *
     * @param str 1
     * @return
     */
    public static String decrypt(String str) {
        // 非标准密文，直接返回
        if (!str.startsWith("encrypt-")) {
            return str;
        }

        // String[] split = str.split(":");
        // String modelStr = split[0];
        // String iv = split[1];
        // String data = split[2];

        String[] split = str.split("-");
        int algo = NumberUtil.toInt(split[1]);
        int model = NumberUtil.toInt(split[2]);
        String data = split[3];

        if (algo == 0 && model == 0) {
            return decryptAesCbc(data);
        } else if (algo == 0 && model == 1) {
            return decryptAesGcm(data);
        }

        return null;
    }

    public static String encryptAesCbc(String rawText) {
        try {
            return "encrypt-0-0-" + AesUtil.encryptCBC(workKey, rawText);
        } catch (NoSuchPaddingException | NoSuchAlgorithmException | InvalidAlgorithmParameterException
            | InvalidKeyException | BadPaddingException | IllegalBlockSizeException e) {
            throw new CommonCoreException("加密失败， 模式=AEC_CBC", e);
        }
    }

    public static String decryptAesCbc(String encryptText) {
        try {
            return AesUtil.decryptCBC(workKey, encryptText);
        } catch (NoSuchPaddingException | NoSuchAlgorithmException | InvalidAlgorithmParameterException
            | InvalidKeyException | BadPaddingException | IllegalBlockSizeException | DecoderException e) {
            throw new CommonCoreException("解密失败， 模式=AEC_CBC", e);
        }
    }

    public static String encryptAesGcm(String rawText) {
        try {
            return "encrypt-0-1-" + AesUtil.encryptGCM(workKey, rawText);
        } catch (NoSuchPaddingException | NoSuchAlgorithmException | InvalidAlgorithmParameterException
            | InvalidKeyException | BadPaddingException | IllegalBlockSizeException e) {
            throw new CommonCoreException("加密失败， 模式=AEC_GCM", e);
        }
    }

    public static String decryptAesGcm(String encryptText) {
        try {
            return AesUtil.decryptGCM(workKey, encryptText);
        } catch (NoSuchPaddingException | NoSuchAlgorithmException | InvalidAlgorithmParameterException
            | InvalidKeyException | BadPaddingException | IllegalBlockSizeException | DecoderException e) {
            throw new CommonCoreException("解密失败， 模式=AEC_GCM", e);
        }
    }

    // public static String decrypt(String encryptText) {
    // if (!encryptText.startsWith("encrypt")) {
    // return encryptText;
    // }
    //
    // String[] split = encryptText.split(":");
    // String head = split[0];
    // String iv = split[1];
    // String data = split[2];
    //
    // return "aa";
    // }
}
