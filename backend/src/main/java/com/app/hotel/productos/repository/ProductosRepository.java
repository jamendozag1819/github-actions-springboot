package com.app.hotel.productos.repository;

import com.app.hotel.productos.model.entity.Producto;
import org.springframework.data.jpa.repository.JpaRepository;

public interface ProductosRepository extends JpaRepository <Producto, Integer>  {

}
