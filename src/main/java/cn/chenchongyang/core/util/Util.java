package cn.chenchongyang.core.util;

import cn.chenchongyang.core.crypto.AesUtil;
import cn.chenchongyang.core.crypto.RootKeyUtil;
import org.apache.commons.codec.digest.HmacAlgorithms;
import org.apache.commons.codec.digest.HmacUtils;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

public class Util {



    public static void main(String[] args) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException {
        String hexString= "E02A97AAC0C456E58F4C633539B53FB55E7A57DDD91744292C95BABA5FC93D5C";
        System.out.println("key:" + AesUtil.encryptGCM(RootKeyUtil.getRootKey(), hexString));
        System.out.println("mac:" + hmacSha256(RootKeyUtil.getRootKey(),hexString));
    }

    private static String hmacSha256(byte[] key, String value) {
        return new HmacUtils(HmacAlgorithms.HMAC_SHA_256, key)
                .hmacHex(value);
    }
}
