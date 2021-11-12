package cn.chenchongyang.core.crypto;

import org.bouncycastle.crypto.PBEParametersGenerator;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.generators.PKCS5S2ParametersGenerator;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.Security;

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
     * 生成密文长度
     */
    private static final int KEY_SIZE = 32 * 8;

    static {
        if (Security.getProperty(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    private PBKDF2Util() {
    }

    public static String encryptPBKDF2WithSHA256(char[] password, byte[] salt) {
        return EncodeUtil.toHex(encryptPBKDF2WithSHA256b(password, salt));
    }

    public static byte[] encryptPBKDF2WithSHA256b(char[] password, byte[] salt) {
        PKCS5S2ParametersGenerator generator = new PKCS5S2ParametersGenerator(new SHA256Digest());
        generator.init(PBEParametersGenerator.PKCS5PasswordToUTF8Bytes(password), salt, ITERATION_COUNT);
        KeyParameter keyParameter = (KeyParameter) generator.generateDerivedMacParameters(KEY_SIZE);
        return keyParameter.getKey();
    }
}
