package com.app.hotel.personas.model.mapper;

import com.app.hotel.personas.model.dto.PersonaDto;
import com.app.hotel.personas.model.entity.Persona;
import lombok.NoArgsConstructor;
import org.springframework.stereotype.Component;

import java.time.LocalDateTime;


@Component
@NoArgsConstructor
public class PersonaMapper {

    public PersonaDto toDto(Persona entity) {
        PersonaDto.PersonaDtoBuilder dtoBuilder = PersonaDto.builder();

        dtoBuilder.id(entity.getId());
//        dtoBuilder.title(entity.getTitle());
//        dtoBuilder.description(entity.getDescription());
        dtoBuilder.fechaCreado(entity.getFechaCreado());
        dtoBuilder.fechaActualizado(entity.getFechaActualizado());

        return dtoBuilder.build();
    }

    public Persona toEntity(PersonaDto dto) {
        Persona entity = new Persona();

        entity.setId(dto.getId());
        setEntity(dto, entity);
        entity.setFechaCreado(LocalDateTime.now());

        return entity;
    }

    public void setEntity(PersonaDto dto, Persona entity) {
        setDtoToEntity(dto, entity);
        entity.setFechaActualizado(LocalDateTime.now());
    }

    private void setDtoToEntity(PersonaDto dto, Persona entity) {
//        entity.setTitle(dto.getTitle());
//        entity.setDescription(dto.getDescription());
    }
}
