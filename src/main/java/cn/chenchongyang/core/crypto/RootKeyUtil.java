package cn.chenchongyang.core.crypto;


import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.codec.digest.HmacAlgorithms;
import org.apache.commons.codec.digest.HmacUtils;
import org.apache.commons.lang3.ArrayUtils;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.IOException;
import java.io.InputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Properties;

public class RootKeyUtil {

    private static final String root_part1 = "AC06A59DFA9D0AB40EE014414635CC08998141BBC74072BAD0B3EC854F95057EB4ABDB757F3F8A139FE3DC8E0ABCCE1D6E4F959DC6F13118CA0BBFCBF11477B232FC808197D9680F17279E21632AC676440F5937BB25542F5D100A8B44CB9571BEE12A7AC7C49D91749C95AC59589CAED550498DB640B4FF8E7A6311054BC921";
    private static final String root_part2 = "65AC434FD39278BA4E5249B7CC1BA1AF461927847F6B12DF5AA3CE35D5A1C97ACC81A16D31C8C70A6C076883DE5A2340521EEB39C8651CEFD066E899D19ACF7C264AF7782608793B58E57C53E5310B805380E4A17967DD8F58BA5371E459DE4D9A1E395010C2683703A35328138F26B5FFF888EA9C395CBE9277EE5874A4BE15";
    private static final String root_part3 = "A34F9B9B0E838D8B7FF81F3FEAD996788A4012829A21E224D080703D11197C78A55E95232A6BE44B41F7D31B55C6908EED35134116E0E9368C0E8C3205FD9CF6013F24A12DEA9FE93FCAF4DC5201B4BC7D362ACAF0F837DB07BE71935943AC791392205B47DEEBDC8996044B86145E4A2D67230F2566B92087757C2A70A315ED";

    private static final String root_salt = "154D3B72D66CAF9222DFA60B88B7ACC5";

    private static byte[] workKey;
    private static byte[] rootKey;


    static {
        init();
    }

    public static void init() {
        try {
            int minLength = Math.min(Math.min(root_part1.length(), root_part2.length()), root_part3.length());
            char[] password = new char[minLength];
            for (int i = 0; i < minLength; i++) {
                password[i] = (char) (root_part1.charAt(i) ^ root_part2.charAt(i) ^ root_part3.charAt(i));
            }
            // 随机运算
            byte[] root = PBKDF2Util.encryptPBKDF2WithSHA256b(password, Hex.decodeHex(root_salt));
            //获取有效秘钥
            rootKey = ArrayUtils.subarray(root, 0, 32);
            initWorkKey();
        } catch (DecoderException | InvalidAlgorithmParameterException | NoSuchPaddingException | IllegalBlockSizeException | IOException | NoSuchAlgorithmException | BadPaddingException | InvalidKeyException e) {
            throw new CryptoException(e);
        }
    }


    public static void initWorkKey() throws IOException, DecoderException, InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException {
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
        workKey = Hex.decodeHex(workKey0);
    }

    public static byte[] getWorkKey0() {
        return workKey.clone();
    }

    public static byte[] getRootKey() {
        return rootKey.clone();
    }


    private static String hmacSha256(byte[] key, String value) {
        return new HmacUtils(HmacAlgorithms.HMAC_SHA_256, key)
                .hmacHex(value).toUpperCase();
    }


}
