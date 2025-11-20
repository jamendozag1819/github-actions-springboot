package com.app.hotel.reservas.model.dto;

import com.app.hotel.reservas.model.entity.EstadoReserva;
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
public class ReservaDto {
    private Integer id;
    private Integer idCliente;
    private Integer idHabitacion;
    private Integer idEmpleado;
    private DecimalFormat montoTotal;
    private LocalDateTime fechaReserva;
    private LocalDateTime fechaEntrada;
    private LocalDateTime fechaSalida;
    private EstadoReserva estado;
    private LocalDateTime fechaCreado;
    private LocalDateTime fechaActualizado;
}
