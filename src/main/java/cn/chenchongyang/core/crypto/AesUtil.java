package cn.chenchongyang.core.crypto;


import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.lang3.StringUtils;

import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * @author 陈崇洋
 * @since 2021-01-01
 */
public final class AesUtil {

    private static final String CBC_ALGORITHM_CIPHER = "AES/CBC/PKCS5Padding";

    private static final String GCM_ALGORITHM_CIPHER = "AES/GCM/NoPadding";

    private static final String AES_ALGORITHM = "AES";

    private static final int IV_LEN = 16;

    private static final int T_LEN_BITS = 96;

    private AesUtil() {
    }

    /**
     * AES_CBC模式加密
     *
     * @param secret 秘钥
     * @param planTest 待加密明文
     * @return 摘要，hex编码
     * @throws NoSuchPaddingException
     * @throws NoSuchAlgorithmException
     * @throws InvalidAlgorithmParameterException
     * @throws InvalidKeyException
     * @throws BadPaddingException
     * @throws IllegalBlockSizeException
     */
    public static String encryptCBC(byte[] secret, String planTest)
            throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException,
            InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        SecretKeySpec secretKeySpec = new SecretKeySpec(secret, AES_ALGORITHM);
        Cipher cipher = Cipher.getInstance(CBC_ALGORITHM_CIPHER);
        IvParameterSpec iv = new IvParameterSpec(SecureRandomUtil.randomByte(IV_LEN));
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, iv);
        byte[] doFinal = cipher.doFinal(planTest.getBytes(StandardCharsets.UTF_8));
        return toHex(iv.getIV()) + ":" + toHex(doFinal);
    }

    /**
     * AES_CBC模式解密
     *
     * @param secret 秘钥
     * @param cipherText hex密文
     * @return utf-8明文
     * @throws NoSuchPaddingException
     * @throws NoSuchAlgorithmException
     * @throws InvalidAlgorithmParameterException
     * @throws InvalidKeyException
     * @throws BadPaddingException
     * @throws IllegalBlockSizeException
     * @throws DecoderException
     */
    public static String decryptCBC(byte[] secret, String cipherText)
            throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException,
            InvalidKeyException, BadPaddingException, IllegalBlockSizeException, DecoderException {
        String[] split = StringUtils.split(cipherText, ":");
        SecretKeySpec secretKeySpec = new SecretKeySpec(secret, AES_ALGORITHM);
        Cipher cipher = Cipher.getInstance(CBC_ALGORITHM_CIPHER);
        IvParameterSpec iv = new IvParameterSpec(toByte(split[0]));
        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, iv);
        byte[] doFinal = cipher.doFinal(toByte(split[1]));
        return toString(doFinal);
    }

    /**
     * AES_GCM模式加密
     *
     * @param secret 秘钥
     * @param planTest 待加密明文
     * @return 摘要，hex编码
     * @throws NoSuchPaddingException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     * @throws BadPaddingException
     * @throws IllegalBlockSizeException
     */
    public static String encryptGCM(byte[] secret, String planTest)
            throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException,
            IllegalBlockSizeException, InvalidAlgorithmParameterException {
        SecretKeySpec secretKeySpec = new SecretKeySpec(secret, AES_ALGORITHM);
        Cipher cipher = Cipher.getInstance(GCM_ALGORITHM_CIPHER);
        GCMParameterSpec iv = new GCMParameterSpec(T_LEN_BITS, SecureRandomUtil.randomByte(IV_LEN));
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, iv);
        byte[] doFinal = cipher.doFinal(planTest.getBytes(StandardCharsets.UTF_8));
        return toHex(iv.getIV()) + ":" + toHex(doFinal);
    }

    /**
     * AES_GCM模式解密
     *
     * @param secret 秘钥
     * @param cipherText hex密文
     * @return utf-8明文
     * @throws NoSuchPaddingException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     * @throws BadPaddingException
     * @throws IllegalBlockSizeException
     * @throws DecoderException
     */
    public static String decryptGCM(byte[] secret, String cipherText)
            throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException,
            IllegalBlockSizeException, DecoderException, InvalidAlgorithmParameterException {
        String[] split = StringUtils.split(cipherText, ":");
        SecretKey secretKeySpec = new SecretKeySpec(secret, AES_ALGORITHM);
        Cipher cipher = Cipher.getInstance(GCM_ALGORITHM_CIPHER);
        GCMParameterSpec iv = new GCMParameterSpec(T_LEN_BITS, toByte(split[0]));
        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, iv);
        byte[] doFinal = cipher.doFinal(toByte(split[1]));
        return toString(doFinal);
    }

    private static String toHex(byte[] bytes) {
        return Hex.encodeHexString(bytes, false);
    }

    private static String toString(byte[] bytes) {
        return new String(bytes, StandardCharsets.UTF_8);
    }

    private static byte[] toByte(String hexStr) throws DecoderException {
        return Hex.decodeHex(hexStr);
    }
}