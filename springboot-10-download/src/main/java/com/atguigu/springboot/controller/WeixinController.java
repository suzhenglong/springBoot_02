package com.atguigu.springboot.controller;

import com.atguigu.springboot.utils.HttpGetUtil;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

/**
 * @Description:
 * @author: zhenglongsu@163.com
 * @date: 2019.10.30 17:33
 */
@RestController("/mc")
public class WeixinController {

    @RequestMapping("/openid")
    public @ResponseBody
    String GetGZHOpenid(HttpServletRequest request, HttpServletResponse response) throws IOException {

        String code = request.getParameter("code");//获取code
        Map params = new HashMap();
        params.put("secret", "2afc703f33bb4f88c9c310a7188b4f82");
        params.put("appid", "wxcef2dd312f6ec807");
        params.put("grant_type", "authorization_code");
        params.put("code", code);
        String result = HttpGetUtil.httpRequestToString(
                "https://api.weixin.qq.com/sns/oauth2/access_token", params);
        System.out.println(result);
        return result;
    }
}
