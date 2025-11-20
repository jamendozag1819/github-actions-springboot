package com.app.hotel.common.responses;

public class OffsetPaginatedResponse<T> extends ResponseFactory<T> {
    public OffsetPaginatedResponse(boolean success, String message, T result) {
        super(success, message, result);
    }
}

