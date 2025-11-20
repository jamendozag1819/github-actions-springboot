package com.app.hotel.auth.controller;

import com.app.hotel.auth.model.dto.AuthDto;
import com.app.hotel.auth.service.AuthServiceImpl;
import com.app.hotel.common.responses.ResponseFactory;
import com.app.hotel.usuarios.model.dto.UsuarioDto;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@Validated
@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthServiceImpl authService;

    @PostMapping("/signup")
    public ResponseEntity<?> registrarCuenta(@RequestBody AuthDto authDto) {
        UsuarioDto result = authService.registrarCuenta(authDto);

        ResponseFactory<UsuarioDto> response = ResponseFactory.success("registrado correctamente", result);
        return new ResponseEntity<>(response, HttpStatus.OK);
    }

    @PostMapping("/signin")
    public ResponseEntity<?> iniciarSesion(@RequestBody AuthDto authDto) {
        UsuarioDto result = authService.iniciarSesion(authDto);

        ResponseFactory<UsuarioDto> response = ResponseFactory.success("success", result);
        return new ResponseEntity<>(response, HttpStatus.OK);
    }
}
