package cn.jojo.og.encryption.encryption.enums;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import lombok.Getter;

/**
 * 加密操作枚举
 *
 * @author JOJO
 */
@Getter
public enum CryptographicOperationEnum {
    /**
     * 加密
     */
    ENCRYPTION(1),
    /**
     * 返回脱敏
     */
    RETURN_DESENSITIZATION(2),
    /**
     * 返回全明文
     */
    RETURN_FULLPLAINTEXT(3),
    /**
     * 返回密文
     */
    RETURN_CIPHERTEXT(4);
    private final Integer value;

    private static Map<Integer, CryptographicOperationEnum> pool = new HashMap<>();

    static {
        for (CryptographicOperationEnum et : CryptographicOperationEnum.values()) {
            pool.put(et.getValue(), et);
        }
    }

    CryptographicOperationEnum(Integer value) {
        this.value = value;
    }

    public static boolean isAllow(Integer type) {
        if (type == null) {
            return false;
        }
        return Arrays.stream(values()).anyMatch(v -> v.value.equals(type));
    }

    public static CryptographicOperationEnum getByValue(Integer value) {
        if (null == value) {
            //默认返回脱敏
            return CryptographicOperationEnum.pool.get(2);
        }
        return CryptographicOperationEnum.pool.get(value);
    }

}
