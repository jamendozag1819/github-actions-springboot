package com.app.hotel.productos.controller;

import com.app.hotel.productos.mapper.ProductoMapper;
import com.app.hotel.productos.model.dto.ProductoDto;
import com.app.hotel.productos.model.entity.Producto;
import com.app.hotel.productos.repository.ProductosRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.stream.Collectors;

@Service
public class ProductoController {

    @Autowired
    private ProductosRepository productosRepository;

    @Autowired
    private ProductoMapper productoMapper;

    public List<ProductoDto> listarTodos() {
        List<Producto> productos = productosRepository.findAll();
        return productos.stream()
                .map(productoMapper::toDto)
                .collect(Collectors.toList());
    }

    public ProductoDto guardarProducto(ProductoDto productoDto) {
        Producto producto = productoMapper.toEntity(productoDto);
        Producto productoGuardado = productosRepository.save(producto);
        return productoMapper.toDto(productoGuardado);
    }

    public ProductoDto obtenerPorId(int id) {
        Producto producto = productosRepository.findById(id).orElse(null);
        return producto != null ? productoMapper.toDto(producto) : null;
    }

    public void eliminarProducto(int id) {
        productosRepository.deleteById(id);
    }
}