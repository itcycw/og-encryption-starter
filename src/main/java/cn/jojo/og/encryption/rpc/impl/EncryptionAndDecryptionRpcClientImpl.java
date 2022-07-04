package cn.jojo.og.encryption.rpc.impl;

import cn.jojo.infra.sdk.api.metadata.IRpcResult;
import cn.jojo.og.encryption.encryption.exception.EncryptionAndDecryptException;
import cn.jojo.og.encryption.rpc.EncryptionAndDecryptionRpcClient;
import cn.tinman.sharedservices.security.api.dto.EnhanceBatchDecryptReq;
import cn.tinman.sharedservices.security.api.dto.EnhanceBatchEncryptReq;
import cn.tinman.sharedservices.security.api.dto.EnhanceDecryptReq;
import cn.tinman.sharedservices.security.api.dto.EnhanceDecryptResp;
import cn.tinman.sharedservices.security.api.dto.EnhanceEncryptReq;
import cn.tinman.sharedservices.security.api.dto.EnhanceEncryptResp;
import cn.tinman.sharedservices.security.api.enums.SceneType;
import cn.tinman.sharedservices.security.api.enums.UserType;
import cn.tinman.sharedservices.security.api.service.EnhanceEncryptApi;
import cn.tinman.sharedservices.security.api.utils.SignHelper;
import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONObject;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.stream.Collectors;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.collections.CollectionUtils;
import org.apache.commons.collections.MapUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.dubbo.config.annotation.Reference;
import org.apache.logging.log4j.util.Strings;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.util.Assert;

/**
 * @author Cw
 * @Classname EncryptionAndDecryptionRpcClientImpl
 * @Description
 * @Date 2022/6/9 15:32
 */
@Component
@Slf4j
public class EncryptionAndDecryptionRpcClientImpl implements EncryptionAndDecryptionRpcClient {

    @Reference
    private EnhanceEncryptApi enhanceEncryptApi;

    @Value("${og-ci-security.accessId:100001}")
    private String accessId;

    @Value("${og-ci-security.secret:MIIBCgKCAQEAnLdoA3ba57YHBAenYbLGTcdC48VVvVVDXV6N}")
    private String secret;

    /**
     * @description: 单个加密
     * @param:
     * @return: java.lang.String
     * @author: Cw
     * @date: 2022/5/6 15:42
     */
    @Override
    public String encrypt(String data, String enOrDecryptDataType) {
        EnhanceEncryptReq encryptReq = new EnhanceEncryptReq();
        //分配给接入方的accessId
        encryptReq.setAccessId(accessId);
        encryptReq.setData(data);
        //加密的数据类型 参照API中的EnOrDecryptDataType
        encryptReq.setDataType(enOrDecryptDataType);
        encryptReq.setTimestamp(System.currentTimeMillis());
        //生成签名
        String sign = generateSign(encryptReq, secret);
        encryptReq.setSign(sign);
        IRpcResult<EnhanceEncryptResp> iRpcResult;
        try {
            iRpcResult = enhanceEncryptApi.encrypt(encryptReq);
            if (Objects.nonNull(iRpcResult) && iRpcResult.checkSuccess() && Objects.nonNull(iRpcResult.getData())) {
                return iRpcResult.getData().getCipherText();
            }
        } catch (Exception e) {
            log.error("根据req={}进行单个加密异常!", JSON.toJSONString(encryptReq), e);
            throw new EncryptionAndDecryptException("加解密服务异常，请联系系统管理员");
        }

        return Strings.EMPTY;
    }


    /**
     * @description:批量加密；加密数据列表长度限制为100以内
     * @param:
     * @return: java.lang.String
     * @author: Cw
     * @date: 2022/5/6 15:46
     */
    @Override
    public Map<String, String> batchEncrypt(HashSet plaintextSet, String enOrDecryptDataType) {
        //校验批量处理的数量
        checkSetSize(plaintextSet);
        EnhanceBatchEncryptReq encryptReq = new EnhanceBatchEncryptReq();
        //分配给接入方的accessId
        encryptReq.setAccessId(accessId);
        // 需要加密的数据列表
        encryptReq.setData(plaintextSet);
        encryptReq.setTimestamp(System.currentTimeMillis());
        //加密的数据类型 参照API中的EnOrDecryptDataType
        encryptReq.setDataType(enOrDecryptDataType);
        //生成签名
        String sign = generateSign(encryptReq, secret);
        encryptReq.setSign(sign);
        IRpcResult<List<EnhanceEncryptResp>> iRpcResult;
        try {
            iRpcResult = enhanceEncryptApi.batchEncrypt(encryptReq);
            if (Objects.nonNull(iRpcResult) && iRpcResult.checkSuccess() && CollectionUtils
                .isNotEmpty(iRpcResult.getData())) {
                return iRpcResult.getData().stream()
                    .collect(Collectors.toMap(EnhanceEncryptResp::getData, EnhanceEncryptResp::getCipherText));
            }
        } catch (Exception e) {
            log.error("根据req={}进行批量加密异常!", JSON.toJSONString(encryptReq), e);
            throw new EncryptionAndDecryptException("加解密服务异常，请联系系统管理员");
        }

        return MapUtils.EMPTY_MAP;
    }

    /**
     * @description:单个脱敏
     * @param:
     * @return: java.lang.String
     * @author: Cw
     * @date: 2022/5/6 15:45
     */
    @Override
    public String decrypt(String cipherText) {
        if (StringUtils.isEmpty(cipherText)) {
            return cipherText;
        }
        EnhanceDecryptReq decryptReq = new EnhanceDecryptReq();
        //分配给接入方的accessId
        decryptReq.setAccessId(accessId);
        decryptReq.setTimestamp(System.currentTimeMillis());
        decryptReq.setUserType(UserType.SYSTEM);
        decryptReq.setScene(SceneType.QUERY);
        //系统accessId或者员工id
        decryptReq.setRoleId(accessId);
        //当前ip
//        decryptReq.setIp(getHostAddress());
        //查询数据对应的用户id
//        decryptReq.setUserId(getCurrentLoginId());
        //解密用途 :100字符以内
        decryptReq.setApplication(SceneType.QUERY);
        // 需要解密的数据密文
        decryptReq.setCipherText(cipherText);
        //生成签名
        String sign = generateSign(decryptReq, secret);
        decryptReq.setSign(sign);
        IRpcResult<EnhanceDecryptResp> iRpcResult;
        try {
            iRpcResult = enhanceEncryptApi.decrypt(decryptReq);
            if (Objects.nonNull(iRpcResult) && iRpcResult.checkSuccess() && Objects.nonNull(iRpcResult.getData())) {
                return iRpcResult.getData().getDecryptData();
            }
        } catch (Exception e) {
            log.error("根据req={}进行单个脱敏异常!", JSON.toJSONString(decryptReq), e);
            throw new EncryptionAndDecryptException("加解密服务异常，请联系系统管理员");
        }
        return Strings.EMPTY;
    }


    /**
     * @description:批量脱敏；解密密文列表长度限制为100以内
     * @param:
     * @return: java.lang.String
     * @author: Cw
     * @date: 2022/5/6 15:47
     */
    @Override
    public Map<String, String> batchDecrypt(HashSet cipherTextSet) {
        //校验批量处理的数量
        checkSetSize(cipherTextSet);
        EnhanceBatchDecryptReq decryptReq = new EnhanceBatchDecryptReq();
        //分配给接入方的accessId
        decryptReq.setAccessId(accessId);
        decryptReq.setTimestamp(System.currentTimeMillis());
        decryptReq.setUserType(UserType.SYSTEM);
        decryptReq.setScene(SceneType.QUERY);
        //系统accessId或者员工id
        decryptReq.setRoleId(accessId);
        //当前ip
//        decryptReq.setIp(getHostAddress());
        //查询数据对应的用户id
//        decryptReq.setUserId(getCurrentLoginId());
        //解密用途 :100字符以内
        decryptReq.setApplication(SceneType.QUERY);
        // 要解密的密文列表
        decryptReq.setCipherTexts(cipherTextSet);
        //生成签名
        String sign = generateSign(decryptReq, secret);
        decryptReq.setSign(sign);
        IRpcResult<List<EnhanceDecryptResp>> iRpcResult;
        try {
            iRpcResult = enhanceEncryptApi.batchDecrypt(decryptReq);
            if (Objects.nonNull(iRpcResult) && iRpcResult.checkSuccess() && CollectionUtils
                .isNotEmpty(iRpcResult.getData())) {
                return iRpcResult.getData().stream()
                    .collect(Collectors
                        .toMap(EnhanceDecryptResp::getCipherText, EnhanceDecryptResp::getDecryptData));
            }
        } catch (Exception e) {
            log.error("根据req={}进行批量解密异常!", JSON.toJSONString(decryptReq), e);
            throw new EncryptionAndDecryptException("加解密服务异常，请联系系统管理员");
        }

        return MapUtils.EMPTY_MAP;
    }


    /**
     * @description:单个明文解密调用
     * @param:
     * @return: java.lang.String
     * @author: Cw
     * @date: 2022/5/6 15:45
     */
    @Override
    public String decryptByFullPlaintext(String cipherText) {
        EnhanceDecryptReq decryptReq = new EnhanceDecryptReq();
        //分配给接入方的accessId
        decryptReq.setAccessId(accessId);
        decryptReq.setTimestamp(System.currentTimeMillis());
        decryptReq.setUserType(UserType.SYSTEM);
        decryptReq.setScene(SceneType.QUERY);
        //系统accessId或者员工id
        decryptReq.setRoleId(accessId);
        //当前ip
//        decryptReq.setIp(getHostAddress());
        //查询数据对应的用户id
//        decryptReq.setUserId(getCurrentLoginId());
        //解密用途 :100字符以内
        decryptReq.setApplication(SceneType.QUERY);
        // 需要解密的数据密文
        decryptReq.setCipherText(cipherText);
        //生成签名
        String sign = generateSign(decryptReq, secret);
        decryptReq.setSign(sign);
        IRpcResult<EnhanceDecryptResp> iRpcResult;
        try {
            iRpcResult = enhanceEncryptApi.decryptByFullPlaintext(decryptReq);
            if (Objects.nonNull(iRpcResult) && iRpcResult.checkSuccess() && Objects.nonNull(iRpcResult.getData())) {
                return iRpcResult.getData().getDecryptData();
            }
        } catch (Exception e) {
            log.error("根据req={}进行单个明文解密调用异常!", JSON.toJSONString(decryptReq), e);
            throw new EncryptionAndDecryptException("加解密服务异常，请联系系统管理员");
        }
        return Strings.EMPTY;
    }

    /**
     * @description:批量明文解密调用；解密密文列表长度限制为100以内
     * @param:
     * @return: java.lang.String
     * @author: Cw
     * @date: 2022/5/6 15:47
     */
    @Override
    public Map<String, String> batchDecryptByFullPlaintext(HashSet cipherTextSet) {
        //校验批量处理的数量
        checkSetSize(cipherTextSet);
        EnhanceBatchDecryptReq decryptReq = new EnhanceBatchDecryptReq();
        //分配给接入方的accessId
        decryptReq.setAccessId(accessId);
        decryptReq.setTimestamp(System.currentTimeMillis());
        decryptReq.setUserType(UserType.SYSTEM);
        decryptReq.setScene(SceneType.QUERY);
        //系统accessId或者员工id
        decryptReq.setRoleId(accessId);
        //当前ip
//        decryptReq.setIp(getHostAddress());
        //查询数据对应的用户id
//        decryptReq.setUserId(getCurrentLoginId());
        //解密用途 :100字符以内
        decryptReq.setApplication(SceneType.QUERY);
        // 要解密的密文列表
        decryptReq.setCipherTexts(cipherTextSet);
        //生成签名
        String sign = generateSign(decryptReq, secret);
        decryptReq.setSign(sign);
        IRpcResult<List<EnhanceDecryptResp>> iRpcResult;
        try {
            iRpcResult = enhanceEncryptApi.batchDecryptByFullPlaintext(decryptReq);
            if (Objects.nonNull(iRpcResult) && iRpcResult.checkSuccess() && CollectionUtils
                .isNotEmpty(iRpcResult.getData())) {
                return iRpcResult.getData().stream()
                    .collect(Collectors
                        .toMap(EnhanceDecryptResp::getCipherText, EnhanceDecryptResp::getDecryptData));
            }
        } catch (Exception e) {
            log.error("根据req={}进行批量明文解密调用异常!", JSON.toJSONString(decryptReq), e);
            throw new EncryptionAndDecryptException("加解密服务异常，请联系系统管理员");
        }

        return MapUtils.EMPTY_MAP;
    }


    /**
     * @description: 生成签名;每次对新加解密的调用必须传入签名，即公共对象的sign，在API包中集成了对sign的生成方法。调用cn.tinman.sharedservices.security.api.utils.SignHelper类的generateSign方法生成签名。
     * @param: o
     * @param: secret
     * @return: java.lang.String
     * @author: Cw
     * @date: 2022/5/6 16:18
     */
    private String generateSign(Object o, String secret) {
        return SignHelper.generateSign(JSONObject.parseObject(JSON.toJSONString(o)), secret);
    }

    /**
     * @description: 校验批量处理的数量
     * @param: set
     * @return: void
     * @author: Cw
     * @date: 2022/5/7 15:03
     */
    private void checkSetSize(HashSet set) {
        Assert.isTrue(CollectionUtils.isNotEmpty(set) && set.size() <= 100, "参数异常! 批量处理的数量必须大于0 小于等于100");
    }

    /**
     * @description: 获取本服务器的IP地址如
     * @param:
     * @return: java.lang.String
     * @author: Cw
     * @date: 2022/5/31 14:37
     */
//    private String getHostAddress() {
//        //获取本服务器的IP地址如：PC-20140317PXKX/192.168.0.121
//        InetAddress address;
//        try {
//            address = InetAddress.getLocalHost();
//        } catch (UnknownHostException e) {
//            log.error("获取本服务器的IP信息异常!");
//            throw new RuntimeException("获取本服务器的IP信息异常");
//        }
//
//        return address.getHostAddress();
//    }

}
