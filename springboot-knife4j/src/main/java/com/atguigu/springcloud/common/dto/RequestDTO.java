package com.atguigu.springcloud.common.dto;

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
 * @Title: RequestDTO
 * @Description: 公共报文头
 * @date 2020/4/9 18:59
 */
@Data
@ApiModel(value = "公共查询请求报文头")
public class RequestDTO implements Serializable {

    private static final long serialVersionUID = -6558671294068003369L;
    // 全局业务流水号
    @ApiModelProperty(value = "全局业务流水号", example = "123123123123123", required = true, position = 1000)
    @NotNull
    private String requestGlobalJnlNo;
    // 上游系统流水号
    @ApiModelProperty(value = "上游流水号", example = "123123123123123", required = true, position = 1001)
    @NotNull
    private String requestJnlNo;
    //   渠道编号
    @ApiModelProperty(value = "业务发起渠道号", example = "WP", required = true, position = 1003)
    @NotNull
    private ChannelCode requestChannelCode;
    @ApiModelProperty(value = "上游渠道Id", example = "WP", required = true, position = 1004)
    @NotNull
    private ChannelId requestChannelId;
    // 交易请求时间
    @NotNull
    @ApiModelProperty(value = "请求时间", example = "2020-02-13 12:00:00", dataType = "date", required = true, position = 1005)
    @DateTimeFormat(pattern = "yyyy-MM-dd HH:mm:ss")
    @JsonFormat(pattern = "yyyy-MM-dd HH:mm:ss", timezone = "GMT+8", shape = JsonFormat.Shape.STRING)
    private Date requestDate;
    // 交易请求客户序列号
    @ApiModelProperty(value = "交易请求客户序列号", example = "8000001", position = 1006)
    private Long requestCifSeq;
    // 交易请求用户序列号
    @ApiModelProperty(value = "交易请求客户序列号", example = "800000101", position = 1007)
    private Long requestUserSeq;
}
