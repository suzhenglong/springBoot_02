package com.atguigu.springcloud.exception;

import com.alibaba.fastjson.JSON;

import com.atguigu.springcloud.common.command.BaseCommandResponse;
import com.atguigu.springcloud.common.exception.BizException;
import com.atguigu.springcloud.common.utils.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.BeansException;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseBody;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.Locale;

/**
 * @author wangxupeng
 * @ProjectName
 * @Title: GlobalExceptionHandler
 * @Description: 异常统一处理
 * @date 2020/4/9 20:13
 */
@ControllerAdvice
public class GlobalExceptionHandler implements ApplicationContextAware {

    private static final Log LOGGER = LogFactory.getLog(GlobalExceptionHandler.class);
    private static final String ERROR_SPLIT = ";";
    private ApplicationContext applicationContext;
    // 系统码
    @Value(value = "${applicationCode:22}")
    private String applicationCode = "22";

    @ExceptionHandler(value = Exception.class)
    @ResponseBody
    public Object bizExceptionHandler(HttpServletRequest request, Exception exception,
                                      HttpServletResponse response) {
        //系统级异常，错误码固定为-1，提示语固定为系统繁忙，请稍后再试
        String requestGlobalJnlNo = request.getParameter("requestGlobalJnlNo");
        String requestChannelId = request.getParameter("requestChannelId");
        String requestJnlNo = request.getParameter("requestJnlNo");
        BaseCommandResponse baseCommandResponse = new BaseCommandResponse(this.applicationCode + "9999",
                exception.getMessage());
        baseCommandResponse.setRequestGlobalJnlNo(requestGlobalJnlNo);
        baseCommandResponse.setRequestChannelId(requestChannelId);
        baseCommandResponse.setRequestJnlNo(requestJnlNo);
        //如果是业务逻辑异常，返回具体的错误码与提示信息
        if (exception instanceof BizException) {
            BizException bizException = (BizException) exception;
            //TODO 目前暂时只支持中文
            Locale locale = Locale.CHINA;
            String errorMessage = applicationContext
                    .getMessage(bizException.getCode(), bizException.getArgs(), locale);
            //TODO 对返回的翻译信息进行切割，获取实际返回码以及返回信息
            if (!StringUtils.isStringEmpty(errorMessage)) {
                int index = errorMessage.indexOf(ERROR_SPLIT);
                if (index > 0) {
                    String respCode = applicationCode + errorMessage.substring(0, index);
                    String respMessage = errorMessage.substring(index + 1);
                    baseCommandResponse.setRespCode(respCode);
                    baseCommandResponse.setRespMessage(respMessage);
                }
            }
        } else {
            //对系统级异常进行日志记录
            LOGGER.error("系统异常:" + exception.getMessage(), exception);
        }
        String resultJson = JSON.toJSONString(baseCommandResponse);
        return resultJson;
    }

    @Override
    public void setApplicationContext(ApplicationContext applicationContext) throws BeansException {
        this.applicationContext = applicationContext;
    }
}
