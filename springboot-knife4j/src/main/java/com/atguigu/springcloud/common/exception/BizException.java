package com.atguigu.springcloud.common.exception;

import lombok.Data;
import lombok.ToString;

/**
 * @author wangxupeng
 * @ProjectName
 * @Title: BizException
 * @Description: TODO
 * @date 2020/4/9 19:22
 */
@Data
@ToString
public class BizException extends RuntimeException {

    /**
     * 错误码
     */
    private String code;

    private Object[] args = new Object[0];

    public BizException(String messageKey) {
        super(messageKey);
        this.code = messageKey;
    }

    public BizException(String messageKey, Object[] args) {
        super(messageKey);
        this.code = messageKey;
        this.args = args;
    }
}
