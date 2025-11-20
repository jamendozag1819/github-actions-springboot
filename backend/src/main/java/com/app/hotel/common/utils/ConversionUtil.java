package com.app.hotel.common.utils;

public class ConversionUtil {

    public static int stringToInt(String str) throws NumberFormatException {
        return Integer.parseInt(str);
    }

    public static double stringToDouble(String str) throws NumberFormatException {
        return Double.parseDouble(str);
    }

    public static String intToString(int number) {
        return String.valueOf(number);
    }

    public static String doubleToString(double number) {
        return String.valueOf(number);
    }
}

