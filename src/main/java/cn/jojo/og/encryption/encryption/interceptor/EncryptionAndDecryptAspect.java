package cn.jojo.og.encryption.encryption.interceptor;


import static cn.jojo.og.encryption.encryption.enums.CryptographicOperationEnum.ENCRYPTION;

import cn.jojo.infra.sdk.api.metadata.IPageResp;
import cn.jojo.og.encryption.encryption.annotation.DecryptType;
import cn.jojo.og.encryption.encryption.annotation.OpenDecrypt;
import cn.jojo.og.encryption.encryption.annotation.OpenEncryption;
import cn.jojo.og.encryption.encryption.enums.CryptographicOperationEnum;
import cn.jojo.og.encryption.service.EncryptionAndDecryptionService;
import java.lang.reflect.Parameter;
import java.util.Collection;
import javax.annotation.Resource;
import lombok.extern.slf4j.Slf4j;
import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.Around;
import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.annotation.Pointcut;
import org.aspectj.lang.reflect.MethodSignature;
import org.springframework.stereotype.Component;
import org.springframework.stereotype.Service;

/**
 * @author macro
 * @date 2022/6/1
 * @description 请求拦截处理加解密
 **/
@Component
@Aspect
@Slf4j
@Service
public class EncryptionAndDecryptAspect {

    @Pointcut(value = "@annotation(cn.jojo.og.encryption.encryption.annotation.OpenEncryption)")
    public void methodEncryption() {
    }

    @Pointcut(value = "@annotation(cn.jojo.og.encryption.encryption.annotation.OpenDecrypt)")
    public void methodDecrypt() {
    }

    @Pointcut(value = "@annotation(cn.jojo.og.encryption.encryption.annotation.DecryptType)")
    public void pararmDecrypt() {
    }

    @Resource
    private EncryptionAndDecryptionService encryptionAndDecryptionService;

    @Around(value = "methodEncryption() || methodDecrypt() || pararmDecrypt()")
    public Object authDeal(ProceedingJoinPoint jp) throws Throwable {
        Object responseObj;
        try {
            MethodSignature methodSignature = (MethodSignature) jp.getSignature();
            Object[] request = jp.getArgs();
            // 判断是否需要加密处理
            OpenEncryption isEncryption = methodSignature.getMethod().getAnnotation(OpenEncryption.class);
            if (isEncryption != null) {
                // 判断是否需要对请求参数解密
                for (Object object : request) {
                    if (object instanceof Collection) {
                        Collection collection = (Collection) object;
                        collection.forEach(var -> {
                            encryptionAndDecryptionService.privacyEncryptionOrDecryption(var, ENCRYPTION);
                        });
                    } else {
                        encryptionAndDecryptionService.privacyEncryptionOrDecryption(object, ENCRYPTION);
                    }
                }
            }

            // 执行方法
            responseObj = jp.proceed();

            // 判断是否需要解密
            OpenDecrypt isDecrypt = methodSignature.getMethod().getAnnotation(OpenDecrypt.class);
            if (isDecrypt != null) {
                //获取解密类型
                //优先从方法上注解获取(默认为脱敏处理)
                CryptographicOperationEnum operationEnum = isDecrypt.decryptType();
                //其次获取方法入参配置的解密类型
                operationEnum = getCryptographicOperationEnum(operationEnum, methodSignature, request);
                if (responseObj instanceof Collection) {
                    Collection collection = (Collection) responseObj;
                    for (Object var : collection) {
                        encryptionAndDecryptionService.privacyEncryptionOrDecryption(var, operationEnum);
                    }
                } else {
                    //针对于分页返回结果做特殊处理
                    if (IPageResp.class == responseObj.getClass()) {
                        IPageResp iPageResp = (IPageResp) responseObj;
                        for (Object resp : iPageResp.getPageRecords()) {
                            encryptionAndDecryptionService.privacyEncryptionOrDecryption(resp, operationEnum);
                        }
                    } else {
                        encryptionAndDecryptionService.privacyEncryptionOrDecryption(responseObj, operationEnum);
                    }
                }
            }
        } catch (Throwable e) {
            log.error("加解密异常：{}", e.getMessage(), e);
            throw e;
        }
        return responseObj;
    }

    /**
     * @description: 获取解密类型
     * @param: operationEnum
     * @param: request
     * @return: cn.jojo.og.encryption.encryption.enums.CryptographicOperationEnum
     * @author: Cw
     * @date: 2022/6/22 17:57
     */
    private CryptographicOperationEnum getCryptographicOperationEnum(CryptographicOperationEnum operationEnum,
        MethodSignature methodSignature,
        Object[] request) {
        // 取出对应的注解
        int index = -1;
        boolean hasDecryptType = false;
        Parameter[] parameters = methodSignature.getMethod().getParameters();
        for (Parameter parameter : parameters) {
            index++;
            if (parameter.isAnnotationPresent(DecryptType.class)) {
                hasDecryptType = true;
                break;
            }
        }

        // 判断是否存在注解
        if (hasDecryptType && CryptographicOperationEnum.class == request[index].getClass()) {
            //读取注解后的参数--->获取手动配置解密类型
            operationEnum = (CryptographicOperationEnum) request[index];
        }

        return operationEnum;
    }

}
