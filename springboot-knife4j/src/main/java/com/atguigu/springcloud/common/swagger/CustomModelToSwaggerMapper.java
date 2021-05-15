package com.atguigu.springcloud.common.swagger;

import org.springframework.context.annotation.Primary;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import springfox.documentation.service.Parameter;
import springfox.documentation.swagger2.mappers.ServiceModelToSwagger2MapperImpl;

import java.util.List;
import java.util.stream.Collectors;

/**
 * @author 杜义淙
 * @ProjectName athena-group
 * @Title: CustomModelToSwaggerMapper
 * @Description: 重写 将Document转换成Swagger 类, 根据order进行排序
 * @date 2019-09-22 14:36
 */
@Primary //同一个接口，可能会有几种不同的实现类，而默认只会采取其中一种的情况下
@Component("ServiceModelToSwagger2Mapper")
@Order(Ordered.HIGHEST_PRECEDENCE)
public class CustomModelToSwaggerMapper extends ServiceModelToSwagger2MapperImpl {

    @Override
    protected List<io.swagger.models.parameters.Parameter> parameterListToParameterList(
            List<Parameter> list) {
        //list需要根据order|postion排序
        list = list.stream().sorted((p1, p2) -> Integer.compare(p1.getOrder(), p2.getOrder())).collect(
                Collectors.toList());
        return super.parameterListToParameterList(list);
    }
}
