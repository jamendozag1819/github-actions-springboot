package com.app.hotel.usuarios.service;

import com.app.hotel.usuarios.model.dto.UsuarioDto;
import com.app.hotel.usuarios.model.entity.Usuario;
import com.app.hotel.usuarios.model.mapper.UsuarioMapper;
import com.app.hotel.usuarios.repository.UsuarioRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

@Service
@RequiredArgsConstructor
public class UsuarioServiceImpl implements UsuarioService {

    private final UsuarioRepository usuarioRepository;
    private final UsuarioMapper usuarioMapper;

    @Override
    public List<UsuarioDto> listar() {
        List<Usuario> entityList = usuarioRepository.findAll(); // Leer la lista de entidades de la base de datos con paginación
        Stream<UsuarioDto> streamDto = entityList.stream().map(usuarioMapper::toDto);
        return streamDto.collect(Collectors.toList()); // Mapear las entidades a DTOs y devolver la página resultante
    }

    @Override
    public Page<UsuarioDto> paginar(Pageable pageable) {
        Page<Usuario> entityPage = usuarioRepository.findAll(pageable); // Leer la lista de entidades de la base de datos con paginación
        return entityPage.map(usuarioMapper::toDto); // Mapear las entidades a DTOs y devolver la página resultante
    }

    @Override
    public UsuarioDto obtenerPorId(Long id) {
        return null;
    }

    @Override
    public UsuarioDto guardar(UsuarioDto dto) {
        return null;
    }

    @Override
    public UsuarioDto actualizar(Long id, UsuarioDto dto) {
        return null;
    }

    @Override
    public void eliminar(Long id) {

    }
}
