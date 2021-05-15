package com.atguigu.springcloud.integral.command;

import com.atguigu.springcloud.common.command.BaseCommand;
import io.swagger.annotations.ApiModel;
import io.swagger.annotations.ApiModelProperty;
import lombok.Data;
import lombok.ToString;
import org.springframework.format.annotation.DateTimeFormat;

import javax.validation.constraints.DecimalMax;
import javax.validation.constraints.DecimalMin;
import java.math.BigDecimal;
import java.util.Date;

/**
 * @Description:积分新增
 * @author: zhenglongsu@163.com
 * @date: 2020/4/26 9:38
 */
@Data
@ToString
@ApiModel(value = "积分新增")
public class IntegralCreatedCommand extends BaseCommand {

    private static final long serialVersionUID = 6639151759361865569L;

    @ApiModelProperty(value = "积分批次编号", example = "10000001", required = true, position = 10001)
    private Long integralId;
    @ApiModelProperty(value = "积分简介", example = "秦农银行理财", required = true, position = 10005)
    private String integralIntroduction;
    @ApiModelProperty(value = "积分描述", example = "购买秦农银行理财即可获得58积分", required = true, position = 10010)
    private String integralDescription;
    @DecimalMax(value = "999999999999.99")
    @DecimalMin(value = "0.01")
    @ApiModelProperty(value = "积分单价", example = "100.00", required = true, position = 10015)
    private BigDecimal integralUnitPrice;
    @ApiModelProperty(value = "是否为批量消息1-是 0-不是", example = "1", required = true, position = 10020)
    private Long integralIsBatch;
    @ApiModelProperty(value = "批量编号", example = "100001", position = 10025)
    private Long integralBatchSeq;
    @ApiModelProperty(value = "总数量", example = "110", required = true, position = 10030)
    private int integralTotalQuantity;
    @ApiModelProperty(value = "总积分", example = "1000", required = true, position = 10035)
    private int integralTotal;
    @ApiModelProperty(value = "生效日期", example = "2020-03-04", required = true, position = 10045)
    @DateTimeFormat(pattern = "yyyy-MM-dd")
    private Date effectDate;
    @ApiModelProperty(value = "失效日期", example = "2020-03-05", required = true, position = 10050)
    @DateTimeFormat(pattern = "yyyy-MM-dd")
    private Date failureDate;
    @ApiModelProperty(value = "创建机构编号", example = "100001", required = true, position = 10060)
    private Long deptSeq;
    @ApiModelProperty(value = "创建机构名称", example = "科蓝银行北京分行", position = 10065)
    private String deptName;
    @ApiModelProperty(value = "创建操作员编号", example = "1000000", required = true, position = 10070)
    private String createOperatorSeq;
    @ApiModelProperty(value = "复核操作员编号", example = "10000001", required = true, position = 10075)
    private String reviewOperatorSeq;
}
