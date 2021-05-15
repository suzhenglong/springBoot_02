package com.atguigu.springcloud.integral.querys.dto;

import com.atguigu.springcloud.common.dto.ResponseDTO;
import io.swagger.annotations.ApiModelProperty;
import lombok.Data;
import lombok.ToString;

import java.util.List;

/**
 * @Description:积分查询返回
 * @author: zhenglongsu@163.com
 * @date: 2020/4/27 17:42
 */
@Data
@ToString
public class IntegralQueryResponseDTO extends ResponseDTO {

    private static final long serialVersionUID = 7658175530396339464L;

    @ApiModelProperty(value = "积分查询列表")
    List<IntegralQueryData> list;
}
