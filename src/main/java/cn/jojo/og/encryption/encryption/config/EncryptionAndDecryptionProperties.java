package cn.jojo.og.encryption.encryption.config;

import cn.jojo.og.encryption.rpc.impl.EncryptionAndDecryptionRpcClientImpl;
import javax.annotation.PostConstruct;
import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * @author by Cw
 * @Classname EncryptionAndDecryptionProperties
 * @Description
 * @Date 2022/7/4 18:49
 */
@Data
@ConfigurationProperties(prefix = "og-ci-security")
public class EncryptionAndDecryptionProperties {

    private String accessId;

    private String secret;

    @PostConstruct
    private void init() {
        EncryptionAndDecryptionRpcClientImpl.init(this);
    }
    
}
