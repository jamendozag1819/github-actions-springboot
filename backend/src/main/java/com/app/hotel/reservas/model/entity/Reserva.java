package com.app.hotel.reservas.model.entity;

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
@Table(name = "reservas")
public class Reserva {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Integer id;

    @Column(nullable = false, name = "id_cliente")
    private Integer idCliente;

    @Column(nullable = false, name = "id_habitacion")
    private Integer idHabitacion;

    @Column(nullable = false, name = "id_empleado")
    private Integer idEmpleado;

    @Column(nullable = false, name = "monto_total")
    private DecimalFormat montoTotal;

    @Column(name = "fecha_reserva")
    private LocalDateTime fechaReserva;

    @Column(name = "fecha_entrada")
    private LocalDateTime fechaEntrada;

    @Column(name = "fecha_salida")
    private LocalDateTime fechaSalida;

    @Enumerated(EnumType.STRING)
    @Column(name = "estado", nullable = false)
    private EstadoReserva estado = EstadoReserva.activo;

    @Column(nullable = false, name = "fecha_creado")
    private LocalDateTime fechaCreado;

    @Column(name = "fecha_actualizado")
    private LocalDateTime fechaActualizado;
}
