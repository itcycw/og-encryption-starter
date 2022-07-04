package cn.jojo.og.encryption.encryption.exception;

import java.io.Serializable;
import lombok.Data;

/**
 * @author wuhong
 * @date 2022/6/16
 * @descript
 **/
@Data
public class EncryptionAndDecryptException extends RuntimeException implements Serializable {

    private static final long serialVersionUID = -1400561280091338206L;

    private String code;

    public EncryptionAndDecryptException(String message) {
        super(message);
        code = "security error";
    }

    public EncryptionAndDecryptException(String code, String message) {
        super(message);
        this.code = code;
    }

    public EncryptionAndDecryptException(String message, Throwable cause, String code) {
        super(message, cause);
        this.code = code;
    }

    public EncryptionAndDecryptException(Throwable cause, String code) {
        super(cause);
        this.code = code;
    }

    public EncryptionAndDecryptException(String message, Throwable cause, boolean enableSuppression,
        boolean writableStackTrace, String code) {
        super(message, cause, enableSuppression, writableStackTrace);
        this.code = code;
    }

}
