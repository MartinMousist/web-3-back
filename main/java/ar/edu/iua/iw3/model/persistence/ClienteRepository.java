package ar.edu.iua.iw3.model.persistence;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import ar.edu.iua.iw3.model.Cliente;

@Repository
public interface ClienteRepository extends JpaRepository<Cliente, Long> {  
    // Búsqueda por el código de integración externo (SAP)
    Optional<Cliente> findOneByCodExterno(String codExterno);

    Optional<Cliente> findOneByRazonSocial(String razonSocial);
}