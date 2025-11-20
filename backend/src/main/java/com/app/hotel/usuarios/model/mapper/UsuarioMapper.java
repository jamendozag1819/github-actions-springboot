package com.app.hotel.usuarios.model.mapper;

import com.app.hotel.usuarios.model.dto.UsuarioDto;
import com.app.hotel.usuarios.model.entity.Usuario;
import lombok.NoArgsConstructor;
import org.springframework.stereotype.Component;

import java.time.LocalDateTime;


@Component
@NoArgsConstructor
public class UsuarioMapper {

    public UsuarioDto toDto(Usuario entity) {
        UsuarioDto.UsuarioDtoBuilder dtoBuilder = UsuarioDto.builder();

        dtoBuilder.id(entity.getId());
//        dtoBuilder.title(entity.getTitle());
//        dtoBuilder.description(entity.getDescription());
//        dtoBuilder.fechaCreado(entity.getFechaCreado());
//        dtoBuilder.fechaActualizado(entity.getFechaActualizado());

        return dtoBuilder.build();
    }

    public Usuario toEntity(UsuarioDto dto) {
        Usuario entity = new Usuario();

        entity.setId(dto.getId());
        setEntity(dto, entity);
        entity.setFechaCreado(LocalDateTime.now());

        return entity;
    }

    public void setEntity(UsuarioDto dto, Usuario entity) {
        setDtoToEntity(dto, entity);
        entity.setFechaActualizado(LocalDateTime.now());
    }

    private void setDtoToEntity(UsuarioDto dto, Usuario entity) {
//        entity.setTitle(dto.getTitle());
//        entity.setDescription(dto.getDescription());
    }
}
