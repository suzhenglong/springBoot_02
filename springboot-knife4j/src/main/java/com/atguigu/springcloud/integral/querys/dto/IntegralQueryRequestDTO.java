package com.atguigu.springcloud.integral.querys.dto;

import com.atguigu.springcloud.common.dto.RequestDTO;
import io.swagger.annotations.ApiModelProperty;
import lombok.Data;
import lombok.ToString;
import org.springframework.format.annotation.DateTimeFormat;

import java.util.Date;

/**
 * @Description:积分查询请求参数
 * @author: zhenglongsu@163.com
 * @date: 2020/4/27 16:44
 */
@Data
@ToString
public class IntegralQueryRequestDTO extends RequestDTO {

    private static final long serialVersionUID = 948810799663540042L;

    @ApiModelProperty(value = "积分批次编号", example = "10000001", position = 10005)
    private Long integralId;
    @ApiModelProperty(value = "起始日期", example = "2020-03-05", position = 10010)
    @DateTimeFormat(pattern = "yyyy-MM-dd")
    private Date startDate;
    @ApiModelProperty(value = "截止日期", example = "2020-03-05", position = 10015)
    @DateTimeFormat(pattern = "yyyy-MM-dd")
    private Date endDate;
}
