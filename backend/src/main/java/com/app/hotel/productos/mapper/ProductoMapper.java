package com.app.hotel.productos.mapper;
import com.app.hotel.productos.model.dto.ProductoDto;
import com.app.hotel.productos.model.entity.Producto;
import org.springframework.stereotype.Component;

@Component
public class ProductoMapper {

    // Convertir de Producto a ProductoDto
    public ProductoDto toDto(Producto producto) {
        return ProductoDto.builder()
                .id(producto.getId())
                .nombre(producto.getNombre())
                .descripcion(producto.getDescripcion())
                .precio(producto.getPrecio())
                .stock(producto.getStock())
                .build();
    }

    // Convertir de ProductoDto a Producto
    public Producto toEntity(ProductoDto productoDto) {
        return Producto.builder()
                .id(productoDto.getId())
                .nombre(productoDto.getNombre())
                .descripcion(productoDto.getDescripcion())
                .precio(productoDto.getPrecio())
                .stock(productoDto.getStock())
                .build();
    }
}