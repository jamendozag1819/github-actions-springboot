package com.app.hotel.common.responses;

public class CursorPaginatedResponse<T> extends ResponseFactory<T> {
    public CursorPaginatedResponse(boolean success, String message, T result) {
        super(success, message, result);

    }
}

