package cn.jojo.og.encryption.encryption.annotation;

import static cn.jojo.og.encryption.encryption.enums.CryptographicOperationEnum.RETURN_DESENSITIZATION;

import cn.jojo.og.encryption.encryption.enums.CryptographicOperationEnum;
import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;

/**
 * 是否开启解密数据
 *
 * @author macro
 */
@Documented
@Target({ElementType.METHOD})
@Retention(RetentionPolicy.RUNTIME)
@Order(Ordered.HIGHEST_PRECEDENCE)
public @interface OpenDecrypt {

    /**
     * 解密类型
     *
     * @see cn.jojo.og.encryption.encryption.enums.CryptographicOperationEnum;
     */
    CryptographicOperationEnum decryptType() default RETURN_DESENSITIZATION;

}
