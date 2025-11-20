package com.app.hotel.common.responses;

import lombok.Getter;
import lombok.Setter;

import java.util.List;


@Getter
@Setter
public class ResultCursorPagination<T> {
    private List<T> data;
    private CursorPagination pagination;

    public ResultCursorPagination(List<T> data, CursorPagination pagination,String baseUrl) {
        this.data = data;
        this.pagination = pagination;
        this.calculateCursorPaginationUrls(baseUrl);
        this.fillEmptyPaginationFields();
    }

    private void calculateCursorPaginationUrls(String baseUrl) {
        // Obtener el cursor actual y el límite de la página
        String nextCursor = pagination.getNextCursor();
        String previousCursor = pagination.getPreviousCursor();
        int limit = pagination.getLimit();

        // Calcular la URL de la siguiente página si hay más páginas disponibles
        if (pagination.isHasNextPage() && nextCursor != null) {
            pagination.setNextPageUrl(baseUrl + "?limit=" + limit + "&cursor=" + nextCursor);
        } else {
            pagination.setNextPageUrl(null); // No hay más páginas
        }

        // Calcular la URL de la página anterior si hay una página previa disponible
        if (pagination.isHasPreviousPage() && previousCursor != null) {
            pagination.setPreviousPageUrl(baseUrl + "?limit=" + limit + "&cursor=" + previousCursor);
        } else {
            pagination.setPreviousPageUrl(null); // No hay página anterior
        }
    }

    private void fillEmptyPaginationFields() {
        // Validar `nextPageUrl` y `previousPageUrl` para que sean null si no son aplicables
        if (!pagination.isHasNextPage()) {
            pagination.setNextPageUrl(null); // No hay página siguiente si no hay más datos
        }

        if (!pagination.isHasPreviousPage()) {
            pagination.setPreviousPageUrl(null); // No hay página anterior si estamos en la primera página
        }
    }
}
