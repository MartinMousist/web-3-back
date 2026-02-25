package ar.edu.iua.iw3.model.persistence;

import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;
import ar.edu.iua.iw3.model.Camion;

public interface ICamionRepository extends JpaRepository<Camion, Long> {
    Optional<Camion> findByPatente(String patente);
}
