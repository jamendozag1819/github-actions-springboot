package com.app.hotel.auth.service;

import com.app.hotel.auth.model.dto.AuthDto;
import com.app.hotel.usuarios.model.dto.UsuarioDto;
import org.springframework.stereotype.Component;

@Component
public interface AuthService {
    UsuarioDto registrarCuenta(AuthDto authUsuarioDto);

    UsuarioDto iniciarSesion(AuthDto authDto);

    Boolean cerrarSesion();

    Boolean recuperarContrasenia();

    Boolean resetearContrasenia();
}
