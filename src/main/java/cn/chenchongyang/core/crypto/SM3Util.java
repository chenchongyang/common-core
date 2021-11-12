
package cn.chenchongyang.core.crypto;

import org.apache.commons.codec.binary.Base64;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.SecureRandom;
import java.security.Security;

public class SM3Util {

    static {
        if (Security.getProperty(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    public static String hmacSM3sign(byte[] key, byte[] data) {
        KeyParameter keyParameter = new KeyParameter(key);
        HMac hMac = new HMac(new SHA256Digest());
        hMac.init(keyParameter);
        hMac.update(data, 0, data.length);
        byte[] result = new byte[hMac.getMacSize()];
        hMac.doFinal(result, 0);
        return Base64.encodeBase64String(result);
    }

    public static void main(String[] args) {
        System.out.println(hmacSM3sign(SecureRandom.getSeed(16), SecureRandom.getSeed(32)));
    }
}
