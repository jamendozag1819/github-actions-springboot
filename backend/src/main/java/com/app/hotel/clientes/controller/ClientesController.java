package com.app.hotel.clientes.controller;

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
@RequestMapping("/clientes")
@RequiredArgsConstructor
public class ClienteController extends BaseController {
     private final ClienteServiceImpl clienteService;
@GetMapping
public ResponseEntity<?> obtenerSamples(@ModelAttribute CustomRequest<?> personaRequest) {
        if (personaRequest.getLimit() != null && personaRequest.getPage() != null) {
            int limit = Integer.parseInt(personaRequest.getLimit());
            int page = Integer.parseInt(personaRequest.getPage());

            Page<ClienteDto> clienteDtoPage = clienteService.paginar(PageRequest.of(page - 1, limit));

            List<ClienteDto> result = clienteDtoPage.getContent();
            String baseUrl = RequestUtil.getBaseUrl(getHttpRequest());
            long total = clienteDtoPage.getTotalElements();

            ResponseFactory<ResultOffsetPagination<ClienteDto>> response = ResponseFactory.withOffset(result, total, limit, page, baseUrl);
            return new ResponseEntity<>(response, HttpStatus.OK);
        } else {
            List<ClienteDto> result = clienteService.listar();
            ResponseFactory<List<ClienteDto>> response = ResponseFactory.success(result);
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
    public ResponseEntity<?> crearCliente(@RequestBody ClienteDto clienteDto) {
        ClienteDto result = clienteService.guardar(ClienteDto);

        ResponseFactory<ClienteDto> response = ResponseFactory.success("Guardado correctamente", result);
        return new ResponseEntity<>(response, HttpStatus.OK);
    }

    @PutMapping("/{id}")
    public ResponseEntity<?> actualizarSample(@PathVariable Long id, @RequestBody ClienteDto clienteDto) {
        ClienteDto result = clienteService.actualizar(id, clienteeDto);

        ResponseFactory<ClienteDto> response = ResponseFactory.success("Actualizado correctamente", result);
        return new ResponseEntity<>(response, HttpStatus.OK);
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<?> eliminarCliente(@PathVariable Long id) {
        clienteService.eliminar(id);

        ResponseFactory<Boolean> response = ResponseFactory.success("Eliminado correctamente", true);
        return new ResponseEntity<>(response, HttpStatus.OK);
    }
}