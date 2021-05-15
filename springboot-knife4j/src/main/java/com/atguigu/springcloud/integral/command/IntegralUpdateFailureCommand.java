package com.atguigu.springcloud.integral.command;

import com.atguigu.springcloud.common.command.BaseCommand;
import io.swagger.annotations.ApiModel;
import io.swagger.annotations.ApiModelProperty;
import lombok.*;

/**
 * @Description:积分失效
 * @author: zhenglongsu@163.com
 * @date: 2020/4/26 9:38
 */
@Data
@ToString
@NoArgsConstructor
@AllArgsConstructor
@Builder
@ApiModel(value = "积分失效")
public class IntegralUpdateFailureCommand extends BaseCommand {

    private static final long serialVersionUID = -7218573376415597802L;

    @ApiModelProperty(value = "积分批次编号", example = "10000001", required = true, position = 10001)
    private Long integralId;
    @ApiModelProperty(value = "积分状态", example = "FAIL", required = true, position = 10002)
    private String integralStatus;
}
