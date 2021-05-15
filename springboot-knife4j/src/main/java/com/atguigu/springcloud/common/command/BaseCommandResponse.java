package com.atguigu.springcloud.common.command;

import com.fasterxml.jackson.annotation.JsonFormat;
import io.swagger.annotations.ApiModel;
import io.swagger.annotations.ApiModelProperty;
import lombok.Data;

import java.io.Serializable;
import java.util.Date;

/**
 * @author wangxupeng
 * @ProjectName
 * @Title: BaseCommandResponse
 * @Description: command统一返回对象
 * @date 2020/4/9 18:58
 */
@Data
@ApiModel(value = "公共交易响应报文头")
public class BaseCommandResponse implements Serializable {

    private static final long serialVersionUID = 4979321791423987279L;
    //返回码
    @ApiModelProperty(value = "返回码", position = 100)
    private String respCode = "000000";
    //返回信息
    @ApiModelProperty(value = "返回信息", position = 101)
    private String respMessage = "交易成功";
    //交易返回时间
    @ApiModelProperty(value = "交易返回时间", position = 102)
    @JsonFormat(pattern = "yyyy-MM-dd HH:mm:ss", timezone = "GMT+8")
    private Date respTime;
    //全局业务流水号
    @ApiModelProperty(value = "全局业务流水号", position = 103)
    private String requestGlobalJnlNo;
    //上游流水号
    @ApiModelProperty(value = "上游流水号", position = 104)
    private String requestJnlNo;
    //上游渠道号
    @ApiModelProperty(value = "上游渠道号", position = 105)
    private String requestChannelId;

    public BaseCommandResponse() {
    }

    public BaseCommandResponse(String respCode, String respMessage) {
        this.respCode = respCode;
        this.respMessage = respMessage;
    }
}
