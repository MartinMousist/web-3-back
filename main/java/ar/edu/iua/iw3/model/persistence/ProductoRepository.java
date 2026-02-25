package ar.edu.iua.iw3.model.persistence;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import ar.edu.iua.iw3.model.Producto;

@Repository
public interface ProductoRepository extends JpaRepository<Producto, Long> {  
    // Búsqueda por el código de integración externo (SAP)
    Optional<Producto> findOneByCodExterno(String codExterno);
    
    // Búsqueda por nombre de producto
    Optional<Producto> findOneByNombre(String nombre);
}