package ar.edu.iua.iw3.auth;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface RoleRepository extends JpaRepository<Role, Integer> {
    // ESTA ES LA LÍNEA MÁGICA QUE TE FALTABA
    Optional<Role> findByName(String name);
}