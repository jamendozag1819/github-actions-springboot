package com.app.hotel.usuarios.model.dto;

import com.app.hotel.common.enums.EstadoGlobal;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class UsuarioDto {
    private Integer id;
    private String nombres;
    private String apellidos;
    private String rol;
    private String username;
    private String pwd;
    private EstadoGlobal estado;
    private LocalDateTime fechaCreado;
    private LocalDateTime fechaActualizado;
    private LocalDateTime fechaEliminado;
}
