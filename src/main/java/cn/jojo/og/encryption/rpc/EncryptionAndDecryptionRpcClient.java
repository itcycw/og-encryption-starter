package cn.jojo.og.encryption.rpc;

import java.util.HashSet;
import java.util.Map;

/**
 * @author JOJO
 * @Classname EncryptionAndDecryptionRpcClient
 * @Description
 * @Date 2022/6/9 15:29
 */
public interface EncryptionAndDecryptionRpcClient {

    String encrypt(String data, String enOrDecryptDataType);

    Map<String, String> batchEncrypt(HashSet plaintextSet, String enOrDecryptDataType);

    String decrypt(String cipherText);

    Map<String, String> batchDecrypt(HashSet cipherTextSet);

    String decryptByFullPlaintext(String cipherText);

    Map<String, String> batchDecryptByFullPlaintext(HashSet cipherTextSet);

}
