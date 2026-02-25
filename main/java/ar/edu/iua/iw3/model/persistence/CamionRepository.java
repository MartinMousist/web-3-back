package ar.edu.iua.iw3.model.persistence;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import ar.edu.iua.iw3.model.Camion;

@Repository
public interface CamionRepository extends JpaRepository<Camion, Long> {
    // Búsqueda por el código de integración externo (SAP/TMS)
    Optional<Camion> findOneByCodExterno(String codExterno);
    
    // Búsqueda por patente (identificador único de negocio)
    Optional<Camion> findOneByPatente(String patente);

}