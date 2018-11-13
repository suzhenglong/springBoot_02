package com.atguigu.user;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
 /**
  * @Description:
  *
  *  * 1、引入依赖‘
  *  * 2、配置dubbo的注册中心地址
  *  * 3、引用服务
  *
  * @author: zhenglongsu@163.com
  * @date: 2018.07.19 17:29
  */
@SpringBootApplication
public class ConsumerUserApplication {

    public static void main(String[] args) {
        SpringApplication.run(ConsumerUserApplication.class, args);
    }
}
