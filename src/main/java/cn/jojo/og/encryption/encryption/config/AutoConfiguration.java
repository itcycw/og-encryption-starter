package cn.jojo.og.encryption.encryption.config;

import cn.jojo.og.encryption.encryption.interceptor.EncryptionAndDecryptAspect;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;

/**
 * @author wuhong
 * @date 2022/6/6
 * @descript
 **/
@Configuration
@ComponentScan("cn.jojo.og.encryption")
@EnableConfigurationProperties(EncryptionAndDecryptionProperties.class)
@Slf4j
@ConditionalOnProperty(prefix = "og-ci-security", name = "enabled", havingValue = "true", matchIfMissing = true)
public class AutoConfiguration {

    private EncryptionAndDecryptionProperties properties;

    public AutoConfiguration(EncryptionAndDecryptionProperties properties) {
        this.properties = properties;
    }

    @ConditionalOnMissingBean
    @Bean
    public EncryptionAndDecryptAspect webLogAspect() {
        return new EncryptionAndDecryptAspect();
    }

}
