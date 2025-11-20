package com.app.hotel.personas.service;

import com.app.hotel.personas.model.dto.PersonaDto;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;

import java.util.List;
import java.util.Optional;

public interface PersonaService {
    List<PersonaDto> listar();

    Page<PersonaDto> paginar(Pageable pageable);

    Optional<PersonaDto> obtenerPorId(Long id);

    PersonaDto guardar(PersonaDto personaDto);

    PersonaDto actualizar(Long id, PersonaDto personaDto);

    void eliminar(Long id);
}
