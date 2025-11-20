package com.app.hotel.common.requests;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class CustomRequest<T> {
    private String page = null;  // Valor predeterminado de 1 para la página
    private String limit = null; // Valor predeterminado de 10 para el límite
    private T entity;
}
