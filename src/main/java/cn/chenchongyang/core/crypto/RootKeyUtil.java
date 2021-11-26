
package cn.chenchongyang.core.crypto;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.codec.digest.HmacAlgorithms;
import org.apache.commons.codec.digest.HmacUtils;
import org.apache.commons.lang3.StringUtils;

import java.io.IOException;
import java.io.InputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Comparator;
import java.util.Properties;
import java.util.stream.Stream;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public class RootKeyUtil {

    /**
     * root key 三段式，第一部分
     */
    private static final String ROOT_PART1 =
        "AC06A59DFA9D0AB40EE014414635CC08998141BBC74072BAD0B3EC854F95057EB4ABDB757F3F8A139FE3DC8E0ABCCE1D6E4F959DC6F13118CA0BBFCBF11477B232FC808197D9680F17279E21632AC676440F5937BB25542F5D100A8B44CB9571BEE12A7AC7C49D91749C95AC59589CAED550498DB640B4FF8E7A6311054BC921";

    /**
     * root key 三段式，第二部分
     */
    private static final String ROOT_PART2 =
        "65AC434FD39278BA4E5249B7CC1BA1AF461927847F6B12DF5AA3CE35D5A1C97ACC81A16D31C8C70A6C076883DE5A2340521EEB39C8651CEFD066E899D19ACF7C264AF7782608793B58E57C53E5310B805380E4A17967DD8F58BA5371E459DE4D9A1E395010C2683703A35328138F26B5FFF888EA9C395CBE9277EE5874A4BE15";

    public static byte[] getRootKey() {
        byte[] root1 = EncodeUtil.hexToByte(ROOT_PART1);
        byte[] root2 = EncodeUtil.hexToByte(ROOT_PART2);
        byte[] root3 = getRootPart3();

        int minLength = getMinLength(root1, root2, root3);
        char[] password = new char[minLength];
        for (int i = 0; i < minLength; i++) {
            password[i] = (char) (root1[i] ^ root2[i] ^ root3[i]);
        }
        return PBKDF2Util.encryptPBKDF2WithSHA256(password, getRootSalt());
    }

    public static byte[] getWorkKey0(byte[] rootKey) {
        try {
            InputStream inputStream = RootKeyUtil.class.getClassLoader().getResourceAsStream("keys.properties");
            Properties properties = new Properties();
            properties.load(inputStream);

            String key0 = (String) properties.get("work.key.0");
            String mac0 = (String) properties.get("work.key.mac.0");

            String workKey0 = AesUtil.decryptGCM(rootKey, key0);
            String workKeyMac0 = hmacSha256(rootKey, workKey0);

            if (!workKeyMac0.equals(mac0)) {
                throw new CryptoException("Invalid secret key!");
            }
            return Hex.decodeHex(workKey0);
        } catch (DecoderException | InvalidAlgorithmParameterException | NoSuchPaddingException
            | IllegalBlockSizeException | IOException | NoSuchAlgorithmException | BadPaddingException
            | InvalidKeyException e) {
            throw new CryptoException("crypto err!", e);
        }
    }

    /**
     * root key 三段式，第三部分，从环境变量中获取
     */
    private static byte[] getRootPart3() {
        String rootPart3 = System.getenv("ROOT_PART3");
        if (StringUtils.isBlank(rootPart3)) {
            throw new IllegalArgumentException("please set env ROOT_PART3");
        }
        return EncodeUtil.hexToByte(rootPart3);
    }

    /**
     * root salt 从环境变量中获取
     */
    private static byte[] getRootSalt() {
        String rootSalt = System.getenv("ROOT_SALT");
        if (StringUtils.isBlank(rootSalt)) {
            throw new IllegalArgumentException("please set env ROOT_SALT");
        }
        return EncodeUtil.hexToByte(rootSalt);
    }

    private static String hmacSha256(byte[] key, String value) {
        return new HmacUtils(HmacAlgorithms.HMAC_SHA_256, key).hmacHex(value).toUpperCase();
    }

    private static int getMinLength(byte[] c1, byte[] c2, byte[] c3) {
        return Stream.of(c1.length, c2.length, c3.length).min(Comparator.comparingInt(o -> o)).get();
    }
}
