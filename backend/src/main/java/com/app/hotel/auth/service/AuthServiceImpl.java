package com.app.hotel.auth.service;

import com.app.hotel.auth.model.dto.AuthDto;
import com.app.hotel.auth.model.mapper.AuthMapper;
import com.app.hotel.auth.repository.AuthRepository;
import com.app.hotel.samples.model.entity.Sample;
import com.app.hotel.usuarios.model.dto.UsuarioDto;
import com.app.hotel.usuarios.model.entity.Usuario;
import com.app.hotel.usuarios.repository.UsuarioRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

@Service
@RequiredArgsConstructor
public class AuthServiceImpl implements AuthService {

    private final UsuarioRepository usuarioRepository;
    private final AuthMapper authMapper;
    private final AuthRepository authRepository;
    private final BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder();

    @Override
    public UsuarioDto registrarCuenta(AuthDto authDto) {
        Usuario entity = new Usuario();
        entity.setUsername(authDto.getUsername());
        entity.setPwd(passwordEncoder.encode(authDto.getPwd()));

        Usuario savedEntity = usuarioRepository.save(entity);

        return authMapper.toDto(savedEntity);
    }

    @Override
    public UsuarioDto iniciarSesion(AuthDto authDto) {
        // Buscar el usuario en la base de datos por su nombre de usuario o correo electrónico
        Usuario usuario = authRepository.findByUsername(authDto.getUsername())
                .orElseThrow(() -> new RuntimeException("Usuario no encontrado"));

        // Verificar la contraseña usando BCryptPasswordEncoder
        if (!passwordEncoder.matches(authDto.getPwd(), usuario.getPwd())) {
            throw new RuntimeException("Contraseña incorrecta");
        }

        // Convertir la entidad Usuario a UsuarioDto
        UsuarioDto usuarioDto = new UsuarioDto();
        usuarioDto.setNombres(authDto.getNombres());
        usuarioDto.setApellidos(authDto.getApellidos());

        // Devolver el DTO del usuario autenticado
        return usuarioDto;
    }

    @Override
    public Boolean cerrarSesion() {
        return null;
    }

    @Override
    public Boolean recuperarContrasenia() {
        return null;
    }

    @Override
    public Boolean resetearContrasenia() {
        return null;
    }
}
