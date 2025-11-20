package com.app.hotel.common.responses;

import lombok.Getter;
import lombok.Setter;

import java.util.List;


@Getter
@Setter
public class ResultOffsetPagination<T> {
    private List<T> data;
    private OffsetPagination pagination;

    public ResultOffsetPagination(List<T> data, OffsetPagination pagination, String baseUrl) {
        this.data = data;
        this.pagination = pagination;
        this.calculatePaginationUrls(baseUrl);
        this.fillEmptyPaginationFields();
    }

    private void calculatePaginationUrls(String baseUrl) {
        int limit = pagination.getPerPage();
        int page = pagination.getCurrentPage();


        int lastPage = (int) Math.ceil((double) pagination.getTotal() / pagination.getPerPage());
        pagination.setLastPage(lastPage);

        // Calcular la URL de la siguiente página si hay más páginas disponibles
        if (pagination.getCurrentPage() < lastPage) {
            pagination.setNextPageUrl(baseUrl + "?limit=" + limit + "&page=" + (page + 1));
        } else {
            pagination.setNextPageUrl(null); // No hay más páginas
        }

        // Calcular la URL de la página anterior si no es la primera página
        if (pagination.getCurrentPage() > 1) {
            pagination.setPrevPageUrl(baseUrl + "?limit=" + limit + "&page=" + (page - 1));
        } else {
            pagination.setPrevPageUrl(null); // No hay página anterior
        }

        // Calcular `from` y `to` en base a la página actual
        int from = (pagination.getCurrentPage() - 1) * pagination.getPerPage() + 1;
        pagination.setFrom(from > pagination.getTotal() ? null : from);

        int to = Math.min(pagination.getFrom() + pagination.getPerPage() - 1, (int) pagination.getTotal());
        pagination.setTo(to < from ? null : to);
    }

    private void fillEmptyPaginationFields() {
        // Si lastPage es null (por ejemplo, cuando total es 0), asegúrate de configurarlo como 1
        if (pagination.getLastPage() == null || pagination.getLastPage() == 0) {
            pagination.setLastPage(1);
        }

        // Si `from` o `to` es null, asegúrate de asignar valores predeterminados
        if (pagination.getFrom() == null) {
            pagination.setFrom(0); // No hay elementos, así que `from` es 0
        }

        if (pagination.getTo() == null) {
            pagination.setTo(0); // No hay elementos, así que `to` es 0
        }

        // Validar `nextPageUrl` y `prevPageUrl` para que sean null si no son aplicables
        if (pagination.getCurrentPage() >= pagination.getLastPage()) {
            pagination.setNextPageUrl(null); // No hay página siguiente si ya estamos en la última
        }

        if (pagination.getCurrentPage() <= 1) {
            pagination.setPrevPageUrl(null); // No hay página anterior si estamos en la primera página
        }
    }
}
