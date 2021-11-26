
package cn.chenchongyang.core.util;

import cn.chenchongyang.core.CommonCoreException;

public class NumberUtil {

    private NumberUtil() {
    }

    public static int toInt(String str) {
        try {
            return Integer.parseInt(str);
        } catch (NumberFormatException e) {
            throw new CommonCoreException("string转换int失败，string=" + str, e);
        }
    }
}
