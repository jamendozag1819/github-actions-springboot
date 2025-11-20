package com.app.hotel.personas.repository;

import com.app.hotel.personas.model.entity.Persona;
import org.springframework.data.jpa.repository.JpaRepository;

public interface PersonaRepository extends JpaRepository<Persona, Long> {
}
