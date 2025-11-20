package com.app.hotel.samples.service;

import com.app.hotel.samples.model.dto.SampleDto;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public interface SampleService {
    List<SampleDto> listar();

    Page<SampleDto> paginar(Pageable pageable);

    SampleDto obtenerPorId(Long id);

    SampleDto guardar(SampleDto sampleDto);

    SampleDto actualizar(Long id, SampleDto sampleDto);

    void eliminar(Long id);
}
