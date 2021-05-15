package com.atguigu.springcloud.integral.service;

import com.atguigu.springcloud.common.command.BaseCommandResponse;
import com.atguigu.springcloud.integral.command.IntegralCreatedCommand;
import com.atguigu.springcloud.integral.command.IntegralUpdateFailureCommand;
import com.atguigu.springcloud.integral.querys.dto.IntegralQueryData;
import com.atguigu.springcloud.integral.querys.dto.IntegralQueryRequestDTO;
import com.atguigu.springcloud.integral.querys.dto.IntegralQueryResponseDTO;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.math.BigDecimal;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

/**
 * @Description:积分管理服务
 * @author: zhenglongsu@163.com
 * @date: 2020/4/26 14:27
 */
@Service
public class IntegralCommandService {

    private Logger logger = LoggerFactory.getLogger(
            IntegralCommandService.class);

    public BaseCommandResponse createIntegral(IntegralCreatedCommand createdCommand) throws Exception {
        logger.info("createdCommand:{}", createdCommand.toString());
        return new BaseCommandResponse();
    }

    public BaseCommandResponse updateIntegralFailure(IntegralUpdateFailureCommand updateFailureCommand) throws Exception {
        logger.info("updateFailureCommand:{}", updateFailureCommand.toString());
        return new BaseCommandResponse();
    }

    public IntegralQueryResponseDTO queryIntegral(IntegralQueryRequestDTO queryRequestDTO) {
        logger.info("queryRequestDTO:{}", queryRequestDTO.toString());
        IntegralQueryResponseDTO queryResponseDTO = new IntegralQueryResponseDTO();
        List<IntegralQueryData> integralQueryDataList = new ArrayList<>();
        for (int i = 0; i < 5; i++) {
            IntegralQueryData data = new IntegralQueryData();
            data.setClientMobilePhone("152013252" + i);
            data.setClientName("张三" + i);
            data.setClientNo(126723462714L + i);
            data.setCreateTime(new Date());
            data.setEffectDate(new Date());
            data.setFailureDate(new Date());
            data.setIntegralAvailableQuantity(100);
            data.setIntegralBatchStatus("sc");
            data.setIntegralId(18783136816L);
            data.setIntegralIssuedQuantity(89);
            data.setIntegralOccupiedQuantity(1000);
            data.setIntegralUnitPrice(new BigDecimal(100.00));
            data.setIssueChannel("PC");
            data.setIssueDate(new Date());
            data.setUseChannel("WC");
            data.setUseTime(new Date());
            integralQueryDataList.add(data);
        }
        queryResponseDTO.setList(integralQueryDataList);
        return queryResponseDTO;
    }
}
