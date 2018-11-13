package com.atguigu.ticket.service;

import com.alibaba.dubbo.config.annotation.Service;
import org.springframework.stereotype.Component;

/**
 * @Description:
 * @Service:将服务发布到注册中心
 * @author: zhenglongsu@163.com
 * @date: 2018.07.19 17:17
 */
@Component
@Service
public class TickerServiceImpl implements TicketService {
    @Override
    public String getTicket() {
        return "<<我不是药神>>";
    }
}
