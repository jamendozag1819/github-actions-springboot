package com.app.hotel.common.utils;

public class ValidationUtil {
    public static boolean isValidGuestCount(int guestCount, int maxOccupancy) {
        return guestCount <= maxOccupancy;
    }
}
