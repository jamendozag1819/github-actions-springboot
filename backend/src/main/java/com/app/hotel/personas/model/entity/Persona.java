package com.app.hotel.personas.model.entity;

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
@Table(name = "personas")
public class Persona {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Integer id;

    @Column(length = 100, nullable = false)
    private String nombre;

    @Column(length = 100, nullable = false)
    private String apellido;

    @Column(name = "tipo_documento", unique = true)
    private Integer tipoDocumento;

    @Column(length = 30, name = "nrodocumento", unique = true)
    private String nroDocumento;

    @Enumerated(EnumType.STRING)
    private Sexo sexo;

    @Column(length = 5)
    private String edad;

    @Column(length = 30)
    private String telefono;

    @Column(length = 30, name = "fecha_nacimiento")
    private String fechaNacimiento;

    @Enumerated(EnumType.STRING)
    @Column(name = "estado_civil")
    private EstadoCivil estadoCivil;

    @Enumerated(EnumType.STRING)
    private Estado estado;

    @Column(name = "fecha_creado", nullable = false)
    private LocalDateTime fechaCreado;

    @Column(name = "fecha_actualizado")
    private LocalDateTime fechaActualizado;
}
