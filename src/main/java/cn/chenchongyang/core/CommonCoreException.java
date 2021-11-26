
package cn.chenchongyang.core;

public class CommonCoreException extends RuntimeException {

    private static final long serialVersionUID = -168309574801221999L;

    public CommonCoreException(String message) {
        super(message);
    }

    public CommonCoreException(String message, Throwable cause) {
        super(message, cause);
    }
}
