package com.app.hotel.reservas.model.dto;

import com.app.hotel.common.enums.EstadoGlobal;
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
public class ReservaConsumoDto {
    private Integer id;
    private Integer idReserva;
    private Integer idProducto;
    private Integer cantidad;
    private DecimalFormat precio;
    private EstadoGlobal estado;
    private LocalDateTime fechaCreado;
    private LocalDateTime fechaActualizado;
}
