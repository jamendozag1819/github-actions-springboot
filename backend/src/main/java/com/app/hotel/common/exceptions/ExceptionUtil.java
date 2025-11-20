package com.app.hotel.common.exceptions;

public class ExceptionUtil {

    public static void logException(Exception e) {
        System.err.println("Exception occurred: " + e.getMessage());
        e.printStackTrace();
    }

    public static String getExceptionStackTrace(Exception e) {
        StringBuilder sb = new StringBuilder();
        for (StackTraceElement element : e.getStackTrace()) {
            sb.append(element.toString()).append("\n");
        }
        return sb.toString();
    }

    public static String getRootCauseMessage(Throwable throwable) {
        Throwable rootCause = throwable;
        while (rootCause.getCause() != null && rootCause != rootCause.getCause()) {
            rootCause = rootCause.getCause();
        }
        return rootCause.getMessage();
    }
}

