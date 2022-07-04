package cn.jojo.og.encryption.encryption.config;

import cn.jojo.og.encryption.encryption.interceptor.EncryptionAndDecryptAspect;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;

/**
 * @author wuhong
 * @date 2022/6/6
 * @descript
 **/
@Configuration
//@Import(cn.jojo.og.encryption.service.impl.EncryptionAndDecryptionServiceImpl.class)
@ComponentScan("cn.jojo.og.encryption")
public class AutoConfiguration {

    @ConditionalOnMissingBean
    @Bean
    public EncryptionAndDecryptAspect webLogAspect() {
        return new EncryptionAndDecryptAspect();
    }

}
