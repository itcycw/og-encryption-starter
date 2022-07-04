package cn.jojo.og.encryption.encryption.annotation;

import static cn.jojo.og.encryption.encryption.enums.EnOrDecryptDataEnum.OTHER;

import cn.jojo.og.encryption.encryption.enums.EnOrDecryptDataEnum;
import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Inherited;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * @author JOJO
 * @Classname Desensitization
 * @Description 加解密字段对应的数据类型
 * @Date 2022/5/27 15:08
 */
@Target({ElementType.FIELD})
@Retention(RetentionPolicy.RUNTIME)
@Inherited
@Documented
public @interface Desensitization {

    /**
     * 加解密字段对应的数据类型
     *
     * @see cn.jojo.og.encryption.encryption.enums.EnOrDecryptDataEnum
     */
    EnOrDecryptDataEnum textType() default OTHER;

}
