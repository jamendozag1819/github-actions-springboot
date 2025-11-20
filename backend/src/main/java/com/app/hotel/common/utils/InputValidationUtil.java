package com.app.hotel.common.utils;

public class InputValidationUtil {

    public static boolean isValidString(String input, int minLength, int maxLength) {
        return input != null && input.length() >= minLength && input.length() <= maxLength;
    }

    public static boolean isValidNumber(String number) {
        return number.matches("\\d+");
    }

    public static boolean isValidUUID(String uuid) {
        return uuid.matches("^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$");
    }
}

