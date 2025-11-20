package com.app.hotel.usuarios.model.entity;

import com.app.hotel.common.enums.EstadoGlobal;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
@Entity
@Table(name = "usuarios")
public class Usuario {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Integer id;

    @Column(length = 100, nullable = false)
    private String nombres;

    @Column(length = 100, nullable = false)
    private String apellidos;

    @Column(length = 50, nullable = false)
    private String rol;

    @Column(length = 100, nullable = false, unique = true)
    private String username;

    @Column(nullable = false)
    private String pwd;

    @Enumerated(EnumType.STRING)
    @Column(length = 20, nullable = false)
    private EstadoGlobal estado = EstadoGlobal.activo; // Valor por defecto

    @Column(nullable = false, name = "fecha_creado")
    private LocalDateTime fechaCreado;

    @Column(name = "fecha_actualizado")
    private LocalDateTime fechaActualizado;

    @Column(name = "fecha_eliminado")
    private LocalDateTime fechaEliminado;
}
