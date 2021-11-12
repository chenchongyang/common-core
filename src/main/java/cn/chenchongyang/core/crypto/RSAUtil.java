package cn.chenchongyang.core.crypto;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * RSA算法工具
 *
 * @author 陈崇洋
 * @since 2021-01-01
 */
public final class RSAUtil {

    /**
     * RSA2签名算法
     */
    public static final String SIGNATURE_RSA2 = "SHA256WithRSA";

    /**
     * RSA签名算法，PSS模式，推荐
     */
    public static final String SIGNATURE_RSA2_PSS = "SHA256WithRSA/PSS";

    /**
     * RSA1签名算法，不推荐
     */
    @Deprecated
    public static final String SIGNATURE_RSA1 = "SHA1WithRSA";

    /**
     * RSA加解密模式
     */
    public static final String RSA_ALGORITHM_OAEP = "RSA/NONE/OAEPWithSHA-256AndMGF1Padding";

    static {
        if (Security.getProperty(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    private RSAUtil() {
    }

    public static String encryptByRSA(String rawText, String publicKey, String algorithm)
            throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException,
            BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance(algorithm);
        cipher.init(Cipher.ENCRYPT_MODE, getPublicKey(publicKey));
        return EncodeUtil.toBase64(cipher.doFinal(EncodeUtil.stringToByte(rawText)));
    }

    public static String encryptByRSAWithOAEP(String rawText, String publicKey)
            throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException,
            BadPaddingException, IllegalBlockSizeException {
        return encryptByRSA(rawText, publicKey, RSA_ALGORITHM_OAEP);
    }

    public static String decryptByRSA(String encryptText, String privateKey, String algorithm)
            throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException,
            BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance(algorithm);
        cipher.init(Cipher.DECRYPT_MODE, getPrivateKey(privateKey));
        return EncodeUtil.toString(cipher.doFinal(EncodeUtil.base64ToByte(encryptText)));
    }

    public static String decryptByRSAWithOAEP(String encryptText, String privateKey)
            throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException,
            BadPaddingException, IllegalBlockSizeException {
        return decryptByRSA(encryptText, privateKey, RSA_ALGORITHM_OAEP);
    }

    public static String signature(String rawText, String privateKey, String algorithm)
            throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, SignatureException {
        Signature signature = Signature.getInstance(algorithm);
        signature.initSign(getPrivateKey(privateKey));
        signature.update(EncodeUtil.stringToByte(rawText));
        return EncodeUtil.toBase64(signature.sign());
    }

    public static String signatureByPSS(String rawText, String privateKey)
            throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, SignatureException {
        return signature(rawText, privateKey, SIGNATURE_RSA2_PSS);
    }

    public static boolean verify(String rawText, String publicKey, String sign, String algorithm)
            throws InvalidKeySpecException, NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Signature signature = Signature.getInstance(algorithm);
        signature.initVerify(getPublicKey(publicKey));
        signature.update(EncodeUtil.stringToByte(rawText));
        return signature.verify(EncodeUtil.base64ToByte(sign));
    }

    public static boolean verifyByPSS(String rawText, String publicKey, String sign)
            throws InvalidKeySpecException, NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        return verify(rawText, publicKey, sign, SIGNATURE_RSA2_PSS);
    }

    private static PublicKey getPublicKey(String publicKey) throws NoSuchAlgorithmException, InvalidKeySpecException {
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(EncodeUtil.base64ToByte(publicKey));
        KeyFactory factory = KeyFactory.getInstance("RSA");
        return factory.generatePublic(keySpec);
    }

    private static PrivateKey getPrivateKey(String privateKey)
            throws NoSuchAlgorithmException, InvalidKeySpecException {
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(EncodeUtil.base64ToByte(privateKey));
        KeyFactory factory = KeyFactory.getInstance("RSA");
        return factory.generatePrivate(keySpec);
    }
}