package com.app.hotel.samples.model.mapper;

import com.app.hotel.samples.model.dto.SampleDto;
import com.app.hotel.samples.model.entity.Sample;
import lombok.NoArgsConstructor;
import org.springframework.stereotype.Component;

import java.time.LocalDateTime;


@Component
@NoArgsConstructor
public class SampleMapper {
    public SampleDto toDto(Sample entity) {
        SampleDto.SampleDtoBuilder dtoBuilder = SampleDto.builder();

        dtoBuilder.id(entity.getId());
        dtoBuilder.title(entity.getTitle());
        dtoBuilder.description(entity.getDescription());
        dtoBuilder.fechaCreado(entity.getFechaCreado());
        dtoBuilder.fechaActualizado(entity.getFechaActualizado());

        return dtoBuilder.build();
    }

    public Sample toEntity(SampleDto dto) {
        Sample entity = new Sample();

        entity.setId(dto.getId());
        setEntity(dto, entity);
        entity.setFechaCreado(LocalDateTime.now());

        return entity;
    }

    public void setEntity(SampleDto dto, Sample entity) {
        setDtoToEntity(dto, entity);
        entity.setFechaActualizado(LocalDateTime.now());
    }

    private void setDtoToEntity(SampleDto dto, Sample entity) {
        entity.setTitle(dto.getTitle());
        entity.setDescription(dto.getDescription());
    }
}