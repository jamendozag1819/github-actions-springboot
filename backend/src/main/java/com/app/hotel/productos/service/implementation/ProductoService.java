package com.app.hotel.productos.service.implementation;

import com.app.hotel.productos.model.entity.Producto;
import com.app.hotel.productos.repository.ProductosRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class ProductoService {

    @Autowired
    private ProductosRepository productosRepository;

    // Obtener todos los productos
    public List<Producto> listarTodos() {
        return productosRepository.findAll();
    }

    // Guardar un nuevo producto
    public Producto guardarProducto(Producto producto) {
        return productosRepository.save(producto);
    }

    // Obtener un producto por ID
    public Producto obtenerPorId(int id) {
        return productosRepository.findById(id).orElse(null);
    }

    // Eliminar un producto por ID
    public void eliminarProducto(int id) {
        productosRepository.deleteById(id);
    }
}