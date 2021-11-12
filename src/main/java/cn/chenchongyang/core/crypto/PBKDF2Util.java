
package cn.chenchongyang.core.crypto;

import org.bouncycastle.crypto.PBEParametersGenerator;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.generators.PKCS5S2ParametersGenerator;
import org.bouncycastle.crypto.params.KeyParameter;

/**
 * @author 陈崇洋
 * @since 2021-02-05
 */
public final class PBKDF2Util {
    /**
     * 迭代次数
     */
    private static final int ITERATION_COUNT = 1000;

    /**
     * bit长度
     */
    private static final int KEY_SIZE_BITS = 256;

    private PBKDF2Util() {
    }

    public static String encryptPBKDF2WithSHA256(String password, byte[] salt) {
        return "security:"
            + EncodeUtil.toHex(encryptPBKDF2WithSHA256(password.toCharArray(), salt, ITERATION_COUNT, KEY_SIZE_BITS));
    }

    public static byte[] encryptPBKDF2WithSHA256(char[] password, byte[] salt) {
        return encryptPBKDF2WithSHA256(password, salt, ITERATION_COUNT, KEY_SIZE_BITS);
    }

    public static byte[] encryptPBKDF2WithSHA256(char[] password, byte[] salt, int iterationCount, int keySize) {
        PKCS5S2ParametersGenerator generator = new PKCS5S2ParametersGenerator(new SHA256Digest());
        generator.init(PBEParametersGenerator.PKCS5PasswordToUTF8Bytes(password), salt, iterationCount);
        KeyParameter keyParameter = (KeyParameter) generator.generateDerivedMacParameters(keySize);
        return keyParameter.getKey();
    }
}
