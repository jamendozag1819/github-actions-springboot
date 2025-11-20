package com.app.hotel.samples.model.entity;

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
@Table(name = "samples")
public class Sample {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(length = 100, nullable = false)
    private String title;

    @Column(length = 250, nullable = false)
    private String description;

    @Column(name = "fecha_creado", nullable = true)
    private LocalDateTime fechaCreado;

    @Column(name = "fecha_actualizado", nullable = true)
    private LocalDateTime fechaActualizado;
}