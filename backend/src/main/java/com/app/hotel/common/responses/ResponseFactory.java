package com.app.hotel.common.responses;

import java.time.LocalDateTime;
import java.util.List;

import lombok.Getter;
import lombok.Setter;
import org.springframework.http.HttpStatus;

@Getter
@Setter
public class ResponseFactory<T> {
    // Getters y setters
    private boolean success;
    private String message;
    private T result;
    private int status;
    private LocalDateTime timestamp;

    // Constructores
    public ResponseFactory(boolean success, String message, T result) {
        this.setSuccess(success);
        this.setMessage(message);
        this.setResult(result);
        this.setStatus(HttpStatus.OK.value());
        this.setTimestamp(LocalDateTime.now());
    }

    // Respuesta exitosa sin paginación
    public static <T> ResponseFactory<T> success(T result) {
        return new ResponseFactory<>(true, "Operación correcta", result);
    }

    // Respuesta exitosa con mensaje personalizado
    public static <T> ResponseFactory<T> success(String message, T result) {
        return new ResponseFactory<>(true, message, result);
    }

    // Respuesta exitosa con paginación por Offset y Limit
    public static <T> OffsetPaginatedResponse<ResultOffsetPagination<T>> withOffset(List<T> data, long total, int perPage, int currentPage, String baseUrl) {
        OffsetPagination pagination = new OffsetPagination(total, perPage, currentPage);
        ResultOffsetPagination<T> result = new ResultOffsetPagination<>(data, pagination, baseUrl);
        return new OffsetPaginatedResponse<>(true, "Operación correcta", result);
    }

    // Respuesta exitosa con paginación basada en cursores
    public static <T> CursorPaginatedResponse<ResultCursorPagination<T>> paginatedSuccessWithCursor(List<T> data, int limit, String nextCursor, String previousCursor, boolean hasNextPage, boolean hasPreviousPage, String baseUrl) {
        CursorPagination pagination = new CursorPagination(limit, nextCursor, previousCursor, hasNextPage, hasPreviousPage);
        ResultCursorPagination<T> result = new ResultCursorPagination<>(data, pagination, baseUrl);
        return new CursorPaginatedResponse<>(true, "Operación correcta", result);
    }
}

