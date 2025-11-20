package com.app.hotel.common.responses;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class CursorPagination {
    private int limit;
    private String nextCursor;
    private String nextPageUrl;
    private String previousCursor;
    private String previousPageUrl;
    private boolean hasNextPage;
    private boolean hasPreviousPage;

    // Constructor, Getters y Setters
    public CursorPagination(int limit, String nextCursor, String previousCursor, boolean hasNextPage, boolean hasPreviousPage) {
        this.limit = limit;
        this.nextCursor = nextCursor;
        this.previousCursor = previousCursor;
        this.hasNextPage = hasNextPage;
        this.hasPreviousPage = hasPreviousPage;
    }
}
