package com.atguigu.springcloud.common.enums;


/**
 * @author 杜义淙
 * @ProjectName athena-group
 * @Title: ChannelCode
 * @Description: 业务渠道号
 * @date 2019-08-20 21:56
 */
public enum ChannelCode {
    PI("PI", "个人网银"),

    PM("PM", "手机银行"),

    EI("EI", "企业网银"),

    EM("EM", "企业手机"),

    WT("WT", "微信银行"),

    WP("WP", "微信小程序"),

    JD("JD", "京东");

    private String code;
    private String description;

    ChannelCode(String code, String description) {
        this.code = code;
        this.description = description;
    }


    public String getCode() {
        return code;
    }

    public String getDescription() {
        return description;
    }
}
