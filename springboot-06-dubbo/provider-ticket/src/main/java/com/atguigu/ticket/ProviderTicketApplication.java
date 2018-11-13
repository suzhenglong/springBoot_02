package com.atguigu.ticket;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * @Description: 1、将服务提供者注册到注册中心
 * 1、引入dubbo和zkclient相关依赖
 * 2、配置dubbo的扫描包和注册中心地址
 * 3、使用@Service发布服务
 * @author: zhenglongsu@163.com
 * @date: 2018.07.19 17:14
 */

@SpringBootApplication
public class ProviderTicketApplication {

    public static void main(String[] args) {
        SpringApplication.run(ProviderTicketApplication.class, args);
    }
}
