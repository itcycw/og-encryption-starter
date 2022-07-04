package cn.jojo.og.encryption.encryption.annotation;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Inherited;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * @author JOJO
 * @Classname Desensitization
 * @Description 是否需要返回密文-解密数据的映射关系 <>p</> 注意：需要在返回dto中新增字段map<>
 * @Date 2022/5/27 15:08
 */
@Target({ElementType.FIELD})
@Retention(RetentionPolicy.RUNTIME)
@Inherited
@Documented
public @interface ExtraEncryption {

}
