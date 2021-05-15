package com.atguigu.springcloud.common.command;

import com.atguigu.springcloud.common.enums.ChannelCode;
import com.atguigu.springcloud.common.enums.ChannelId;
import com.fasterxml.jackson.annotation.JsonFormat;
import io.swagger.annotations.ApiModel;
import io.swagger.annotations.ApiModelProperty;
import lombok.Data;
import org.springframework.format.annotation.DateTimeFormat;

import javax.validation.constraints.NotNull;
import java.io.Serializable;
import java.util.Date;

/**
 * @author wangxupeng
 * @ProjectName
 * @Title: BaseCommand
 * @Description: 基础命令数据（报文头）
 * @date 2020/4/9 18:57
 */
@Data
@ApiModel(value = "公共交易请求报文头")
public class BaseCommand implements Serializable {

    private static final long serialVersionUID = -2768092928078662452L;

    @ApiModelProperty(value = "全局业务流水号", example = "123123123123123", required = true, position = 1000)
    @NotNull
    private String requestGlobalJnlNo;
    @ApiModelProperty(value = "上游流水号", example = "123123123123123", required = true, position = 1001)
    @NotNull
    private String requestJnlNo;
    @ApiModelProperty(value = "业务发起渠道号 PI-个人网银，PM-手机银行，EI-企业网银，EM-企业手机，WT-微信银行，WP-微信小程序，JD-京东", example = "WP", required = true, position = 1003)
    @NotNull
    private ChannelCode requestChannelCode;
    @ApiModelProperty(value = "上游渠道Id CB-基础中心，CC-客户中心，CM-消息中心，CR-路由中心，CL-限额中心，CP-产品中心，CF-资金交换中心，OI-开放平台，PI-个人网银，PM-手机银行，WP-微信公众号，WL-微信小程序，EI-企业网银，EM-企业手机", example = "WP", required = true, position = 1004)
    @NotNull
    private ChannelId requestChannelId;
    // 交易请求时间
    @NotNull
    @ApiModelProperty(value = "请求时间", example = "2020-02-13 12:00:00", required = true, position = 1005)
    @DateTimeFormat(pattern = "yyyy-MM-dd HH:mm:ss")
    @JsonFormat(pattern = "yyyy-MM-dd HH:mm:ss", timezone = "GMT+8", shape = JsonFormat.Shape.STRING)
    private Date requestDate;
    @ApiModelProperty(value = "交易请求客户序列号", example = "8000001", position = 1006)
    private Long requestCifSeq;
    @ApiModelProperty(value = "交易请求用户序列号", example = "800000101", position = 1007)
    private Long requestUserSeq;
}
