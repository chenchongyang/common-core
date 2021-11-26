
package cn.chenchongyang.core.crypto;

import org.apache.commons.codec.DecoderException;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public final class SysCryptUtil {

    private static byte[] workKey;

    private SysCryptUtil() {
    }

    public static void initWorkKeyAndVerifyDigest() {
        byte[] rootKey = RootKeyUtil.getRootKey();
        workKey = RootKeyUtil.getWorkKey0(rootKey);
    }

    public static String aesGcmEncrypt(String rawText) {
        try {
            return AesUtil.encryptGCM(workKey, rawText);
        } catch (NoSuchPaddingException | NoSuchAlgorithmException | InvalidAlgorithmParameterException
            | InvalidKeyException | BadPaddingException | IllegalBlockSizeException e) {
            throw new CryptoException(e);
        }
    }

    public static String aesGcmDecrypt(String encryptText) {
        try {
            return AesUtil.decryptGCM(workKey, encryptText);
        } catch (NoSuchPaddingException | NoSuchAlgorithmException | InvalidAlgorithmParameterException
            | InvalidKeyException | BadPaddingException | IllegalBlockSizeException | DecoderException e) {
            throw new CryptoException(e);
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
