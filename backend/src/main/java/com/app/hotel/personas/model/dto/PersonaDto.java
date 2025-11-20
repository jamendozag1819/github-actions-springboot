package com.app.hotel.personas.model.dto;

import com.app.hotel.personas.model.entity.Estado;
import com.app.hotel.personas.model.entity.EstadoCivil;
import com.app.hotel.personas.model.entity.Sexo;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class PersonaDto {
    private Integer id;
    private String nombre;
    private String apellido;
    private Integer tipoDocumento;
    private String nroDocumento;
    private Sexo sexo;
    private String edad;
    private String telefono;
    private String fechaNacimiento;
    private EstadoCivil estadoCivil;
    private Estado estado;
    private LocalDateTime fechaCreado;
    private LocalDateTime fechaActualizado;
}
