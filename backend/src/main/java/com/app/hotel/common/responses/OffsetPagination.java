package com.app.hotel.common.responses;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class OffsetPagination {
    private long total; // Total de elementos en la base de datos
    private int perPage; // Elementos por página
    private int currentPage; // Página actual
    private Integer lastPage; // Última página disponible
    private String nextPageUrl; // URL para la siguiente página
    private String prevPageUrl; // URL para la página anterior (null si no hay)
    private Integer from; // Primer elemento de la página actual
    private Integer to; // Último elemento de la página actual

    // Constructor, Getters y Setters
    public OffsetPagination(long total, int perPage, int currentPage) {
        this.total = total;
        this.perPage = perPage;
        this.currentPage = currentPage;
    }
}
