package cn.jojo.og.encryption.service.impl;

import static cn.jojo.og.encryption.encryption.enums.CryptographicOperationEnum.ENCRYPTION;
import static cn.jojo.og.encryption.encryption.enums.CryptographicOperationEnum.RETURN_CIPHERTEXT;
import static cn.jojo.og.encryption.encryption.enums.CryptographicOperationEnum.RETURN_FULLPLAINTEXT_OVERWRITE_ORIGINAL;

import cn.jojo.og.encryption.encryption.annotation.Desensitization;
import cn.jojo.og.encryption.encryption.annotation.ExtraEncryption;
import cn.jojo.og.encryption.encryption.enums.CryptographicOperationEnum;
import cn.jojo.og.encryption.rpc.EncryptionAndDecryptionRpcClient;
import cn.jojo.og.encryption.service.EncryptionAndDecryptionService;
import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Objects;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.collections.CollectionUtils;
import org.apache.commons.collections.MapUtils;
import org.apache.commons.lang3.StringUtils;
import org.springframework.stereotype.Service;

/**
 * @author JOJO
 * @Classname EncryptionAndDecryptionServiceImpl
 * @Description
 * @Date 2022/5/27 14:56
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class EncryptionAndDecryptionServiceImpl implements EncryptionAndDecryptionService {

    private final EncryptionAndDecryptionRpcClient encryptionAndDecryptionRpcClient;

    @Override
    public <T> void privacyEncryptionOrDecryption(T source, CryptographicOperationEnum operationEnum) {
        //判空
        if (null == source) {
            return;
        }

        Class<?> clazz = source.getClass();
        Field[] fields = clazz.getDeclaredFields();
        Map<Field, String> fieldMap = new HashMap<>();
        HashMap<String, HashSet> queryMap = new HashMap<>();
        //反射获取需要处理的隐私数据
        Field extraField = getFields(source, fields, fieldMap, queryMap);
        //反射加密/解密隐私数据
        //加密操作
        if (Objects.equals(ENCRYPTION, operationEnum)) {
            encryptedData(source, fieldMap, queryMap);
        } else {
            //解密操作
            decryptData(source, fieldMap, operationEnum, queryMap, extraField);
        }

        return;
    }

    private <T> Field getFields(T source, Field[] fields, Map<Field, String> fieldMap,
        HashMap<String, HashSet> queryMap) {
        Field f = null;
        //反射获取需要加密处理的隐私数据
        for (int i = 0; i < fields.length; i++) {
            Field field = fields[i];
            boolean needHandle = false;

            if (field.getAnnotation(ExtraEncryption.class) != null) {
                f = field;
            }
            if (Modifier.isStatic(field.getModifiers())) {
                continue;
            }
            if (field.getAnnotation(Desensitization.class) == null) {
                continue;
            }

            Desensitization desensitization = field.getAnnotation(Desensitization.class);
            //加解密的数据类型:PHONE、EMAIL、ID_CARD、NAME等
            String textType = desensitization.textType().toString();
            try {
                field.setAccessible(true);
                //实体字段对应的原始内容
                String text = (String) field.get(source);
                if (StringUtils.isNotEmpty(text)) {
                    HashSet hashSet = queryMap.computeIfAbsent(textType, k -> new HashSet<String>());
                    hashSet.add(text);
                    needHandle = true;
                }

                if (needHandle) {
                    fieldMap.put(field, (String) field.get(source));
                }

            } catch (IllegalAccessException e) {
                log.error("反射获取需要加密处理的隐私数据异常!", e);
            }
        }

        return f;
    }


    private <T> void encryptedData(T source, Map<Field, String> fieldMap, HashMap<String, HashSet> queryMap) {
        //反射加密隐私数据
        if (fieldMap.size() > 0) {
            Map<String, Map<String, String>> resultMap = new HashMap<>(queryMap.size());
            queryMap.forEach((k, y) -> resultMap.put(k, batchEncrypt(queryMap.get(k), k)));

            fieldMap.forEach((field, value) -> {
                try {
                    field.setAccessible(true);
                    String textType = field.getAnnotation(Desensitization.class).textType().toString();
                    Map<String, String> encryptMap = resultMap.get(textType);
                    field.set(source, encryptMap.get(value));

                } catch (IllegalAccessException e) {
                    log.error("反射加密隐私数据出现异常!", e);
                }
            });
        }
    }


    private <T> void decryptData(T source, Map<Field, String> fieldMap, CryptographicOperationEnum operationEnum,
        HashMap<String, HashSet> queryMap, Field extraField) {
        //操作类型为解密—返回密文时不做任何处理
        if (RETURN_CIPHERTEXT == operationEnum) {
            return;
        }

        //反射解密隐私数据
        boolean needExtra = Objects.nonNull(extraField);
        if (needExtra && fieldMap.size() > 0) {
            HashSet<String> cipherTextSet = new HashSet<>();
            queryMap.values().stream().filter(o -> CollectionUtils.isNotEmpty(o)).forEach(o -> cipherTextSet.addAll(o));

            //隐私加密数据；k: 脱敏信息， v:密文信息
            Map<String, String> extraEncryptionMap = new HashMap<>();
            Map<String, String> decryptMap = new HashMap<>(cipherTextSet.size());
            switch (operationEnum) {
                //解密-脱敏
                case RETURN_DESENSITIZATION:
                    decryptMap = batchDecrypt(cipherTextSet);
                    break;
                //解密-全明文
                case RETURN_FULLPLAINTEXT:
                    decryptMap = batchDecryptByFullPlaintext(cipherTextSet);
                    break;
                //解密-返回全明文(覆盖原字段)
                case RETURN_FULLPLAINTEXT_OVERWRITE_ORIGINAL:
                    decryptMap = batchDecryptByFullPlaintext(cipherTextSet);
                    break;
                default:
                    break;
            }

            for (Entry<Field, String> entry : fieldMap.entrySet()) {
                Field field = entry.getKey();
                String value = entry.getValue();
                if (RETURN_FULLPLAINTEXT_OVERWRITE_ORIGINAL == operationEnum) {
                    try {
                        field.setAccessible(true);
                        field.set(source, decryptMap.get(value));
                    } catch (IllegalAccessException e) {
                        log.error("反射加密隐私数据出现异常!", e);
                    }
                }

                extraEncryptionMap.put(value, decryptMap.get(value));
            }

            if (MapUtils.isNotEmpty(extraEncryptionMap)) {
                try {
                    extraField.setAccessible(true);
                    extraField.set(source, extraEncryptionMap);
                } catch (IllegalAccessException e) {
                    log.error("反射解密隐私数据额外补充信息时出现异常!", e);
                }
            }

        }
    }


    /**
     * @description: 批量加密
     * @param: data   需要加密的数据集合;加密数据列表长度限制为100以内
     * @param: enOrDecryptDataType   加密的数据类型
     * @return: java.lang.String
     * @author: Cw
     * @date: 2022/5/26 15:19
     */
    private Map<String, String> batchEncrypt(HashSet plaintextSet, String enOrDecryptDataType) {
        if (CollectionUtils.isNotEmpty(plaintextSet)) {
            //批量加密
            return encryptionAndDecryptionRpcClient.batchEncrypt(plaintextSet, enOrDecryptDataType);
        }

        return MapUtils.EMPTY_MAP;
    }

    /**
     * @description: 加密单个文本
     * @param: data   需要加密的数据
     * @param: enOrDecryptDataType   加密的数据类型
     * @return: java.lang.String
     * @author: Cw
     * @date: 2022/5/26 15:19
     */
    private String encrypt(String data, String enOrDecryptDataType) {
        if (StringUtils.isNotEmpty(data)) {
            //单个加密
            return encryptionAndDecryptionRpcClient.encrypt(data, enOrDecryptDataType);
        }

        return data;
    }

    /**
     * @description: 单个脱敏
     * @param: cipherText
     * @return: java.lang.String
     * @author: Cw
     * @date: 2022/5/27 14:24
     */
    private String decrypt(String cipherText) {
        //单个脱敏
        return encryptionAndDecryptionRpcClient.decrypt(cipherText);
    }

    /**
     * @description: 批量脱敏
     * @param: cipherTextSet   需要脱敏的数据集合;数据列表长度限制为100以内
     * @return: java.util.Map<java.lang.String, java.lang.String>
     * @author: Cw
     * @date: 2022/5/27 14:25
     */
    private Map<String, String> batchDecrypt(HashSet cipherTextSet) {
        if (CollectionUtils.isNotEmpty(cipherTextSet)) {
            //批量加密
            return encryptionAndDecryptionRpcClient.batchDecrypt(cipherTextSet);
        }

        return MapUtils.EMPTY_MAP;
    }

    /**
     * @description: 批量明文解密调用；解密密文列表长度限制为100以内
     * @param: cipherTextSet
     * @return: java.util.Map<java.lang.String, java.lang.String>
     * @author: Cw
     * @date: 2022/5/27 16:52
     */
    private Map<String, String> batchDecryptByFullPlaintext(HashSet cipherTextSet) {
        if (CollectionUtils.isNotEmpty(cipherTextSet)) {
            //批量加密
            return encryptionAndDecryptionRpcClient.batchDecryptByFullPlaintext(cipherTextSet);
        }

        return MapUtils.EMPTY_MAP;
    }

}
