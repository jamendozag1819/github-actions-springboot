package com.app.hotel.usuarios.service;

import com.app.hotel.samples.model.dto.SampleDto;
import com.app.hotel.usuarios.model.dto.UsuarioDto;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public interface UsuarioService {
    List<UsuarioDto> listar();

    Page<UsuarioDto> paginar(Pageable pageable);

    UsuarioDto obtenerPorId(Long id);

    UsuarioDto guardar(UsuarioDto dto);

    UsuarioDto actualizar(Long id, UsuarioDto dto);

    void eliminar(Long id);
}
