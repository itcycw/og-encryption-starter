package cn.jojo.og.encryption.service;


import cn.jojo.og.encryption.encryption.enums.CryptographicOperationEnum;

/**
 * @author JOJO
 * @Classname EncryptionAndDecryptionService
 * @Description
 * @Date 2022/5/27 14:55
 */
public interface EncryptionAndDecryptionService {

    <T> void privacyEncryptionOrDecryption(T source, CryptographicOperationEnum operationEnum);
}
