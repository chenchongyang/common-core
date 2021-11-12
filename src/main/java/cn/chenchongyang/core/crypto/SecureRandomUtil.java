
package cn.chenchongyang.core.crypto;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

/**
 * 安全的随机字符生成工具
 *
 * @author 陈崇洋
 * @since 2021-01-01
 */
public final class SecureRandomUtil {

    private SecureRandomUtil() {
    }

    public static byte[] randomByte(int len) throws NoSuchAlgorithmException {
        byte[] b = new byte[len];
        // linux下，该代码严重阻塞，具体原因请百度
        // SecureRandom.getInstanceStrong().nextBytes(b);
        SecureRandom.getInstance("SHA1PRNG").nextBytes(b);
        return b;
    }
}