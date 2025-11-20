package com.app.hotel.auth.model.mapper;

import com.app.hotel.auth.model.dto.AuthDto;
import com.app.hotel.usuarios.model.dto.UsuarioDto;
import com.app.hotel.usuarios.model.entity.Usuario;
import lombok.NoArgsConstructor;
import org.springframework.stereotype.Component;

import java.time.LocalDateTime;


@Component
@NoArgsConstructor
public class AuthMapper {
    public UsuarioDto toDto(Usuario entity) {
        UsuarioDto.UsuarioDtoBuilder dtoBuilder = UsuarioDto.builder();

        dtoBuilder.id(entity.getId());
        dtoBuilder.nombres(entity.getNombres());
        dtoBuilder.apellidos(entity.getApellidos());
        dtoBuilder.username(entity.getUsername());
        dtoBuilder.fechaCreado(entity.getFechaCreado());
        dtoBuilder.fechaActualizado(entity.getFechaActualizado());

        return dtoBuilder.build();
    }
////
//    public Usuario toEntity(AuthDto dto) {
//        Usuario entity = new Usuario();
//
//        entity.setId(dto.getId());
//        setEntity(dto, entity);
//        entity.setFechaCreado(LocalDateTime.now());
//
//        return entity;
//    }

    public void setEntity(AuthDto dto, Usuario entity) {
        setDtoToEntity(dto, entity);
        entity.setFechaActualizado(LocalDateTime.now());
    }

    private void setDtoToEntity(AuthDto dto, Usuario entity) {
        entity.setNombres(dto.getNombres());
        entity.setApellidos(dto.getApellidos());
    }
}