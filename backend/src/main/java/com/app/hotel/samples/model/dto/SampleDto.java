package com.app.hotel.samples.model.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class SampleDto {
    private Long id;
    private String title;
    private String description;
    private LocalDateTime fechaCreado;
    private LocalDateTime fechaActualizado;
}
