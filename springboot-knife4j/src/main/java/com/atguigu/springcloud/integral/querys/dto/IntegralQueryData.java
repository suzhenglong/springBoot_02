package com.atguigu.springcloud.integral.querys.dto;

import com.fasterxml.jackson.annotation.JsonFormat;
import io.swagger.annotations.ApiModelProperty;
import lombok.Data;
import lombok.ToString;
import org.springframework.format.annotation.DateTimeFormat;

import java.io.Serializable;
import java.math.BigDecimal;
import java.util.Date;

/**
 * @Description:积分查询
 * @author: zhenglongsu@163.com
 * @date: 2020/4/27 17:42
 */
@Data
@ToString
public class IntegralQueryData implements Serializable {

    private static final long serialVersionUID = 916406669470451489L;

    @ApiModelProperty(value = "积分批次编号", example = "10000001", position = 10001)
    private Long integralId;
    @ApiModelProperty(value = "积分批次状态", example = "SUCC", position = 10005)
    private String integralBatchStatus;
    @ApiModelProperty(value = "积分单价", example = "100.00", position = 10015)
    private BigDecimal integralUnitPrice;
    @ApiModelProperty(value = "总数量", example = "1110", position = 10020)
    private int integralTotalQuantity;
    @ApiModelProperty(value = "剩余可用数量", example = "1100", position = 10025)
    private int integralAvailableQuantity;
    @ApiModelProperty(value = "已占用数量", example = "10", position = 10030)
    private int integralOccupiedQuantity;
    @ApiModelProperty(value = "已发放数量", example = "100", position = 10035)
    private int integralIssuedQuantity;
    @ApiModelProperty(value = "创建时间", example = "2020-02-13 12:00:00", position = 100040)
    @DateTimeFormat(pattern = "yyyy-MM-dd HH:mm:ss")
    @JsonFormat(pattern = "yyyy-MM-dd HH:mm:ss", timezone = "GMT+8", shape = JsonFormat.Shape.STRING)
    private Date createTime;
    @ApiModelProperty(value = "生效日期", example = "2020-03-04", position = 10045)
    @DateTimeFormat(pattern = "yyyy-MM-dd")
    private Date effectDate;
    @ApiModelProperty(value = "失效日期", example = "2020-03-05", position = 10050)
    @DateTimeFormat(pattern = "yyyy-MM-dd")
    private Date failureDate;
    @ApiModelProperty(value = "积分状态", example = "SUCC", position = 10055)
    private String integralStatus;
    @ApiModelProperty(value = "客户编号", example = "1001", position = 10060)
    private Long clientNo;
    @ApiModelProperty(value = "客户姓名", example = "张三", position = 10065)
    private String clientName;
    @ApiModelProperty(value = "客户手机号码", example = "17733191782", position = 10070)
    private String clientMobilePhone;
    @ApiModelProperty(value = "发放渠道", example = "PC")
    private String issueChannel;
    @ApiModelProperty(value = "发放时间", example = "2020-02-13 12:00:00", position = 10075)
    @DateTimeFormat(pattern = "yyyy-MM-dd HH:mm:ss")
    @JsonFormat(pattern = "yyyy-MM-dd HH:mm:ss", timezone = "GMT+8", shape = JsonFormat.Shape.STRING)
    private Date issueDate;
    @ApiModelProperty(value = "使用渠道", example = "MC", position = 100080)
    private String useChannel;
    @ApiModelProperty(value = "使用时间", example = "2020-02-13 12:00:00", position = 100085)
    @DateTimeFormat(pattern = "yyyy-MM-dd HH:mm:ss")
    @JsonFormat(pattern = "yyyy-MM-dd HH:mm:ss", timezone = "GMT+8", shape = JsonFormat.Shape.STRING)
    private Date useTime;
}
