package com.atguigu.springcloud.common.enums;


/**
 * @author 杜义淙
 * @ProjectName athena-group
 * @Title: ChannelId
 * @Description: 渠道ID
 * @date 2019-09-21 23:26
 */
public enum ChannelId {

    /**
     * Center Base
     */
    CB("CB", "基础中心"),
    /**
     * Center Cif
     */
    CC("CC", "客户中心"),
    /**
     * Center Message
     */
    CM("CM", "消息中心"),
    /**
     * Center Router
     */
    CR("CR", "路由中心"),
    /**
     * Center Limit
     */
    CL("CL", "限额中心"),
    /**
     * Center Product
     */
    CP("CP", "产品中心"),
    /**
     * Center Product
     */
    CF("CF", "资金交换中心"),
    /**
     * Open Api
     */
    OI("OI", "开放平台"),
    /**
     * Person Internet
     */
    PI("PI", "个人网银"),
    /**
     * Person Mobile
     */
    PM("PM", "个人手机"),
    /**
     * Wechat Public
     */
    WP("WP", "微信公众号"),
    /**
     * Wechat LittleProgram
     */
    WL("WL", "微信小程序"),
    /**
     * Enterprise Internet
     */
    EI("EI", "企业网银"),
    /**
     * Enterprise Mobile
     */
    EM("EM", "企业手机");


    private String code;
    private String description;

    ChannelId(String code, String description) {
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
