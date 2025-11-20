package com.app.hotel.samples.controller;

import com.app.hotel.common.controllers.BaseController;
import com.app.hotel.common.requests.CustomRequest;
import com.app.hotel.common.responses.ResponseFactory;
import com.app.hotel.common.responses.ResultOffsetPagination;
import com.app.hotel.common.utils.RequestUtil;
import com.app.hotel.samples.model.dto.SampleDto;
import com.app.hotel.samples.service.SampleServiceImpl;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

import java.util.List;


@Validated
@RestController
@RequestMapping("/samples")
@RequiredArgsConstructor
public class SampleController extends BaseController {

    private final SampleServiceImpl sampleService;

    @GetMapping
    public ResponseEntity<?> obtenerSamples(@ModelAttribute CustomRequest<?> personaRequest) {
        if (personaRequest.getLimit() != null && personaRequest.getPage() != null) {
            int limit = Integer.parseInt(personaRequest.getLimit());
            int page = Integer.parseInt(personaRequest.getPage());

            Page<SampleDto> sampleDtoPage = sampleService.paginar(PageRequest.of(page - 1, limit));

            List<SampleDto> result = sampleDtoPage.getContent();
            String baseUrl = RequestUtil.getBaseUrl(getHttpRequest());
            long total = sampleDtoPage.getTotalElements();

            ResponseFactory<ResultOffsetPagination<SampleDto>> response = ResponseFactory.withOffset(result, total, limit, page, baseUrl);
            return new ResponseEntity<>(response, HttpStatus.OK);
        } else {
            List<SampleDto> result = sampleService.listar();
            ResponseFactory<List<SampleDto>> response = ResponseFactory.success(result);
            return new ResponseEntity<>(response, HttpStatus.OK);
        }
    }

    @GetMapping("/{id}")
    public ResponseEntity<?> obtenerSamplePorId(@PathVariable Long id) {
        SampleDto result = sampleService.obtenerPorId(id);

        ResponseFactory<SampleDto> response = ResponseFactory.success("Operación correcta", result);
        return new ResponseEntity<>(response, HttpStatus.OK);
    }

    @PostMapping
    public ResponseEntity<?> crearSample(@RequestBody SampleDto sampleDto) {
        SampleDto result = sampleService.guardar(sampleDto);

        ResponseFactory<SampleDto> response = ResponseFactory.success("Guardado correctamente", result);
        return new ResponseEntity<>(response, HttpStatus.OK);
    }

    @PutMapping("/{id}")
    public ResponseEntity<?> actualizarSample(@PathVariable Long id, @RequestBody SampleDto sampleDto) {
        SampleDto result = sampleService.actualizar(id, sampleDto);

        ResponseFactory<SampleDto> response = ResponseFactory.success("Actualizado correctamente", result);
        return new ResponseEntity<>(response, HttpStatus.OK);
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<?> eliminarSample(@PathVariable Long id) {
        sampleService.eliminar(id);

        ResponseFactory<Boolean> response = ResponseFactory.success("Eliminado correctamente", true);
        return new ResponseEntity<>(response, HttpStatus.OK);
    }
}
