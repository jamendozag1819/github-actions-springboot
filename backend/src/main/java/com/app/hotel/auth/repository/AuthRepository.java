package com.app.hotel.auth.repository;

import com.app.hotel.usuarios.model.entity.Usuario;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface AuthRepository extends JpaRepository<Usuario, Long> {
    Optional<Usuario> findByUsername(String username);
}
