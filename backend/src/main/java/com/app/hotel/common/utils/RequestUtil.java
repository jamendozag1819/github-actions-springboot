package com.app.hotel.common.utils;

import jakarta.servlet.http.HttpServletRequest;
import org.jetbrains.annotations.NotNull;

import java.util.Collection;
import java.util.Map;
import java.util.Objects;

public class RequestUtil {
    public static String getBaseUrl(@NotNull HttpServletRequest request) {
        // Obtiene el esquema (http o https)
        String scheme = request.getScheme();

        // Obtiene el nombre del servidor
        String serverName = request.getServerName();

        // Obtiene el puerto del servidor
        int serverPort = request.getServerPort();

        // Obtiene el contexto de la aplicación
        String contextPath = request.getContextPath();

        // Obtiene la URI y el query string completo
        String requestUri = request.getRequestURI();

        // Construye el baseUrl incluyendo el path completo
        return scheme + "://" + serverName + ":" + serverPort + contextPath + requestUri;
    }

    // Valida que un objeto no sea null y opcionalmente imprime un mensaje si lo es
    public static <T> boolean isNotNull(T obj, String message) {
        if (obj == null) {
            System.out.println(message);  // Mensaje personalizado
            return false;
        }
        return true;
    }

    // Valida que una cadena de texto no sea nula ni vacía
    public static boolean isNotEmpty(String str, String message) {
        if (str == null || str.trim().isEmpty()) {
            System.out.println(message);  // Mensaje personalizado
            return false;
        }
        return true;
    }

    // Valida que una colección no sea nula ni vacía
    public static <T extends Collection<?>> boolean isNotEmpty(T collection, String message) {
        if (collection == null || collection.isEmpty()) {
            System.out.println(message);  // Mensaje personalizado
            return false;
        }
        return true;
    }

    // Valida que un mapa no sea nulo ni vacío
    public static <K, V> boolean isNotEmpty(Map<K, V> map, String message) {
        if (map == null || map.isEmpty()) {
            System.out.println(message);  // Mensaje personalizado
            return false;
        }
        return true;
    }

    // Valida que un array no sea nulo ni vacío
    public static <T> boolean isNotEmpty(T[] array, String message) {
        if (array == null || array.length == 0) {
            System.out.println(message);  // Mensaje personalizado
            return false;
        }
        return true;
    }

    // Valida que un número no sea nulo ni negativo
    public static <T extends Number> boolean isNotNegative(T number, String message) {
        if (number == null || number.doubleValue() < 0) {
            System.out.println(message);  // Mensaje personalizado
            return false;
        }
        return true;
    }
}

