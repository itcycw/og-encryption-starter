package cn.jojo.og.encryption.encryption.config;

import com.alibaba.fastjson.JSON;
import com.ctrip.framework.apollo.model.ConfigChangeEvent;
import com.ctrip.framework.apollo.spring.annotation.ApolloConfigChangeListener;
import java.util.Set;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.BeansException;
import org.springframework.cloud.context.environment.EnvironmentChangeEvent;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;
import org.springframework.stereotype.Component;

/**
 * @author by Cw
 * @Classname ApolloRefreshConfig
 * @Description
 * @Date 2022/7/4 19:45
 */
@Slf4j
@Component
public class ApolloRefreshConfig implements ApplicationContextAware {

    private ApplicationContext applicationContext;

    @Override
    public void setApplicationContext(ApplicationContext applicationContext) throws BeansException {
        this.applicationContext = applicationContext;
    }

    /**
     * 指定需要监测的配置文件
     */
    @ApolloConfigChangeListener(value = {"application"})
    public void onChange(ConfigChangeEvent changeEvent) {
        Set<String> changedKeys = changeEvent.changedKeys();
        log.info("Apollo changed keys: {}", JSON.toJSONString(changedKeys));
        applicationContext.publishEvent(new EnvironmentChangeEvent(changedKeys));
    }

}
