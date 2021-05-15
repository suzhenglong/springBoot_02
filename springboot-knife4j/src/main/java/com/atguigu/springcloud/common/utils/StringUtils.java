package com.atguigu.springcloud.common.utils;

/**
 * @author wangxupeng
 * @ProjectName
 * @Title: StringUtils
 * @Description: TODO
 * @date 2020/4/9 19:23
 */
public class StringUtils {

    public static Long parseLong(Object value) {
        if (value == null) {
            return null;
        }
        if (value instanceof Long) {
            try {
                return (Long) value;
            } catch (Exception e) {
                return null;
            }
        } else {
            try {
                return new Long(value.toString());
            } catch (Exception e) {
                return null;
            }
        }
    }

    public static boolean isStringEmpty(String str) {
        return null == str || str.trim().length() == 0;
    }
}
