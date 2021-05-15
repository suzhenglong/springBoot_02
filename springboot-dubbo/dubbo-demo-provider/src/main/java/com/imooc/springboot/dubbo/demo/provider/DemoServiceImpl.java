package com.imooc.springboot.dubbo.demo.provider;

import com.alibaba.dubbo.config.annotation.Service;
import com.imooc.springboot.dubbo.demo.DemoService;

@Service
public class DemoServiceImpl implements DemoService {

    @Override
    public String sayHello(String name) {
        return "Hello, " + name + " (from Spring Boot)";
    }

}
