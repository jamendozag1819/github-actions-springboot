package com.app.hotel.common.utils;

import java.time.LocalDate;
import java.time.format.DateTimeFormatter;

public class DateUtil {
    public static String formatLocalDate(LocalDate date) {
        return date.format(DateTimeFormatter.ofPattern("yyyy-MM-dd"));
    }

    public static boolean isDateInRange(LocalDate checkIn, LocalDate checkOut, LocalDate target) {
        return (target.isAfter(checkIn) || target.isEqual(checkIn)) &&
                (target.isBefore(checkOut) || target.isEqual(checkOut));
    }
}
