package com.app.hotel.common.utils;

public class StringUtil {

    public static boolean isNullOrEmpty(String str) {
        return str == null || str.trim().isEmpty();
    }

    public static String capitalizeFirstLetter(String str) {
        if (isNullOrEmpty(str)) {
            return str;
        }
        return str.substring(0, 1).toUpperCase() + str.substring(1).toLowerCase();
    }

    public static String[] splitByDelimiter(String str, String delimiter) {
        return str.split(delimiter);
    }
}
