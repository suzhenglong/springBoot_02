package com.atguigu.springcloud.controller;


import com.atguigu.springcloud.common.command.BaseCommandResponse;
import com.atguigu.springcloud.integral.command.IntegralCreatedCommand;
import com.atguigu.springcloud.integral.command.IntegralUpdateFailureCommand;
import com.atguigu.springcloud.integral.querys.dto.IntegralQueryRequestDTO;
import com.atguigu.springcloud.integral.querys.dto.IntegralQueryResponseDTO;
import com.atguigu.springcloud.integral.service.IntegralCommandService;
import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;

/**
 * @Description: 积分管理包括积分批次查询、新增、失效操作； 积分批次新增、
 * 失效操作需要操作员提交业务申请，复核员进行业务复核，复核通过后生效；
 * @author: zhenglongsu@163.com
 * @date: 2020/4/26 9:33
 */
@Api(tags = "积分管理")
@RestController
@RequestMapping("/api/integral")
public class IntegralController {

    @Autowired
    IntegralCommandService commandService;

    @ApiOperation(value = "积分批次新增")
    @RequestMapping(value = "addIntegral", method = RequestMethod.POST)
    @ResponseStatus(HttpStatus.CREATED)
    public BaseCommandResponse create(@RequestBody IntegralCreatedCommand createdCommand)
            throws Exception {
        return commandService.createIntegral(createdCommand);
    }

    @ApiOperation(value = "积分失效")
    @PutMapping(value = "updateIntegralFailure", method = RequestMethod.PUT)
    @ResponseStatus(HttpStatus.CREATED)
    public BaseCommandResponse updateIntegralFailure(@RequestBody IntegralUpdateFailureCommand updateFailureCommand)
            throws Exception {
        return commandService.updateIntegralFailure(updateFailureCommand);
    }


    @ApiOperation(value = "积分查询")
    @RequestMapping(value = "queryIntegral", method = RequestMethod.GET)
    public IntegralQueryResponseDTO queryIntegral(IntegralQueryRequestDTO queryRequestDTO)
            throws Exception {
        return commandService.queryIntegral(queryRequestDTO);
    }
}
