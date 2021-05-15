package com.atguigu.springcloud.common.dto;

import com.fasterxml.jackson.annotation.JsonFormat;
import io.swagger.annotations.ApiModel;
import io.swagger.annotations.ApiModelProperty;
import lombok.Data;

import java.io.Serializable;
import java.util.Date;

/**
 * @author wangxupeng
 * @ProjectName
 * @Title: ResponseDTO
 * @Description: 公共查询响应报文头
 * @date 2020/4/9 18:59
 */
@Data
@ApiModel(value = "公共查询响应报文头")
public class ResponseDTO implements Serializable {

    //返回码
    @ApiModelProperty(value = "返回码", position = 1000)
    private String respCode = "000000";
    //返回信息
    @ApiModelProperty(value = "返回信息", position = 1001)
    private String respMessage = "交易成功";
    //交易返回时间
    @ApiModelProperty(value = "交易返回时间", position = 1002)
    @JsonFormat(pattern = "yyyy-MM-dd HH:mm:ss", timezone = "GMT+8")
    private Date respTime;
    //全局业务流水号
    @ApiModelProperty(value = "全局业务流水号", position = 1003)
    private String requestGlobalJnlNo;
    //上游流水号
    @ApiModelProperty(value = "上游流水号", position = 1004)
    private String requestJnlNo;
    //上游渠道号
    @ApiModelProperty(value = "上游渠道号", position = 1005)
    private String requestChannelId;

    public ResponseDTO() {
    }

    public ResponseDTO(String respCode, String respMessage) {
        this.respCode = respCode;
        this.respMessage = respMessage;
    }
}

