package com.app.hotel.reservas.model.entity;

import com.app.hotel.common.enums.EstadoGlobal;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.text.DecimalFormat;
import java.time.LocalDateTime;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
@Entity
@Table(name = "reservas_consumo")
public class ReservaConsumo {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Integer id;

    @Column(nullable = false, name = "id_reserva")
    private Integer idReserva;

    @Column(nullable = false, name = "id_producto")
    private Integer idProducto;

    @Column(nullable = false)
    private Integer cantidad;

    @Column(nullable = false)
    private DecimalFormat precio;

    @Enumerated(EnumType.STRING)
    @Column(name = "estado", nullable = false)
    private EstadoGlobal estado = EstadoGlobal.activo; // Valor por defecto

    @Column(nullable = false, name = "fecha_creado")
    private LocalDateTime fechaCreado;

    @Column(name = "fecha_actualizado")
    private LocalDateTime fechaActualizado;
}
