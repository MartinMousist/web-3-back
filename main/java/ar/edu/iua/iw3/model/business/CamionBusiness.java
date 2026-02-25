package ar.edu.iua.iw3.model.business;

import java.util.Optional;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import ar.edu.iua.iw3.model.Camion;
import ar.edu.iua.iw3.model.persistence.CamionRepository;
import lombok.extern.slf4j.Slf4j;

@Service
@Slf4j
public class CamionBusiness implements ICamionBusiness {

    @Autowired
    private CamionRepository camionDAO;

    @Override
    public Camion load(long id) throws NotFoundException, BusinessException {
        Optional<Camion> r;
        try {
            r = camionDAO.findById(id);
        } catch (Exception e) {
            log.error(e.getMessage(), e);
            throw BusinessException.builder().ex(e).build();
        }
        if (r.isEmpty()) {
            throw NotFoundException.builder().message("No se encuentra el Camión id=" + id).build();
        }
        return r.get();
    }

    @Override
    public Camion load(String codExterno) throws NotFoundException, BusinessException {
        Optional<Camion> r;
        try {
            r = camionDAO.findOneByCodExterno(codExterno);
        } catch (Exception e) {
            log.error(e.getMessage(), e);
            throw BusinessException.builder().ex(e).build();
        }
        if (r.isEmpty()) {
            throw NotFoundException.builder().message("No se encuentra el Camión codExterno=" + codExterno).build();
        }
        return r.get();
    }

    @Override
    public Camion save(Camion camion) throws BusinessException {
        try {
            return camionDAO.save(camion);
        } catch (Exception e) {
            throw BusinessException.builder().ex(e).build();
        }
    }

    @Override
    public Camion add(Camion camion) throws FoundException, BusinessException {
        // Verificar si existe por codExterno o patente
        if (camionDAO.findOneByCodExterno(camion.getCodExterno()).isPresent() || 
            camionDAO.findOneByPatente(camion.getPatente()).isPresent()) {
            throw FoundException.builder().message("Ya existe un Camión con ese código externo o patente.").build();
        }
        try {
            return camionDAO.save(camion);
        } catch (Exception e) {
            log.error(e.getMessage(), e);
            throw BusinessException.builder().ex(e).build();
        }
    }
    
    @Override
    public Camion update(Camion camion) throws NotFoundException, BusinessException {
        load(camion.getId());
        try {
            return camionDAO.save(camion);
        } catch (Exception e) {
            log.error(e.getMessage(), e);
            throw BusinessException.builder().ex(e).build();
        }
    }

    @Override
    public void delete(long id) throws NotFoundException, BusinessException {
        load(id);
        try {
            camionDAO.deleteById(id);
        } catch (Exception e) {
            log.error(e.getMessage(), e);
            throw BusinessException.builder().ex(e).build();
        }
    }

    @Override
    public Camion loadByPatente(String patente) throws NotFoundException, BusinessException {
        Optional<Camion> r;
        try {
            r = camionDAO.findOneByPatente(patente);
        } catch (Exception e) {
            log.error(e.getMessage(), e);
            throw BusinessException.builder().ex(e).build();
        }
        if (r.isEmpty()) {
            throw NotFoundException.builder().message("No se encuentra el Camión con patente=" + patente).build();
        }
        return r.get();
    }
}