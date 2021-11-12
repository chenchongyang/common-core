package cn.chenchongyang.core.crypto;

import org.apache.commons.codec.DecoderException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

public final class SysCryptUtil {

    private SysCryptUtil() {
    }

    public static String aesGcmEncrypt(String rawText) {
        try {
            return AesUtil.encryptGCM(RootKeyUtil.getWorkKey0(), rawText);
        } catch (NoSuchPaddingException | NoSuchAlgorithmException | InvalidAlgorithmParameterException | InvalidKeyException | BadPaddingException | IllegalBlockSizeException e) {
            throw new CryptoException(e);
        }
    }

    public static String aesGcmDecrypt(String encryptText) {
        try {
            return AesUtil.decryptGCM(RootKeyUtil.getWorkKey0(), encryptText);
        } catch (NoSuchPaddingException | NoSuchAlgorithmException | InvalidAlgorithmParameterException | InvalidKeyException | BadPaddingException | IllegalBlockSizeException | DecoderException e) {
            throw new CryptoException(e);
        }
    }

    public static String decrypt(String encryptText) {
        if (!encryptText.startsWith("encrypt")) {
            return encryptText;
        }

        String[] split = encryptText.split(":");
        String head = split[0];
        String iv = split[1];
        String data = split[2];

        return "aa";
    }
}
