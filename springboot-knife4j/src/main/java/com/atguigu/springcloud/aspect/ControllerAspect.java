package com.atguigu.springcloud.aspect;

import com.google.gson.Gson;
import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.Around;
import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.annotation.Pointcut;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import javax.servlet.http.HttpServletRequest;

/**
 * @author
 * @ProjectName athena-group
 * @Title: ControllerAspect
 * @Description: Controller 切面
 * @date 2019-12-15 19:52
 */
@Component
@Aspect
public class ControllerAspect {

    private Logger logger = LoggerFactory.getLogger(ControllerAspect.class);

    /**
     * 切点 当前包及其子包
     */
    @Pointcut("execution(public * com.atguigu.*.controller..*.*(..))")
    //@Pointcut("execution(public * com.atguigu.springcloud.controller.*.*(..))")
    public void controller() {
    }

    /**
     * 环切
     */
    @Around("controller()")
    public Object handlerController(ProceedingJoinPoint joinPoint)
            throws Throwable {
        long startTimeMillis = System.currentTimeMillis();

        // 开始打印请求日志
        ServletRequestAttributes attributes = (ServletRequestAttributes) RequestContextHolder.getRequestAttributes();
        HttpServletRequest request = attributes.getRequest();
        // 打印请求 url
        logger.info("URL            : {}", request.getRequestURL().toString());
        logger.info("URI            : {}", request.getRequestURI());
        // 打印 Http method
        logger.info("HTTP Method    : {}", request.getMethod());
        // 打印调用 controller 的全路径以及执行方法
        logger.info("Class Method   : {}.{}", joinPoint.getSignature().getDeclaringTypeName(), joinPoint.getSignature().getName());
        // 打印请求的 IP
        //logger.info("IP             : {}", request.getRemoteAddr());
        // 打印请求入参
        logger.info("Request Args   : {}", new Gson().toJson(joinPoint.getArgs()));
        String requestURI = request.getRequestURI();

        Object result = joinPoint.proceed();
        // 打印出参
        logger.info("Response Args  : {}", new Gson().toJson(result));
        // 执行耗时
        long execTimeMillis = System.currentTimeMillis() - startTimeMillis;
        logger.info("Time-Consuming : {} ms", execTimeMillis);
        return result;
    }
}
