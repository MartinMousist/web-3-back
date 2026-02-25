package ar.edu.iua.iw3.model.business;

import java.util.Optional;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import ar.edu.iua.iw3.model.Chofer;
import ar.edu.iua.iw3.model.persistence.ChoferRepository;
import lombok.extern.slf4j.Slf4j;

@Service
@Slf4j
public class ChoferBusiness implements IChoferBusiness {

    @Autowired
    private ChoferRepository choferDAO;
    
    @Override
    public Chofer load(long id) throws NotFoundException, BusinessException {
        Optional<Chofer> r;
        try {
            r = choferDAO.findById(id);
        } catch (Exception e) {
            log.error(e.getMessage(), e);
            throw BusinessException.builder().ex(e).build();
        }
        if (r.isEmpty()) {
            throw NotFoundException.builder().message("No se encuentra el Chofer id=" + id).build();
        }
        return r.get();
    }

    @Override
    public Chofer load(String codExterno) throws NotFoundException, BusinessException {
        Optional<Chofer> r;
        try {
            r = choferDAO.findOneByCodExterno(codExterno);
        } catch (Exception e) {
            log.error(e.getMessage(), e);
            throw BusinessException.builder().ex(e).build();
        }
        if (r.isEmpty()) {
            throw NotFoundException.builder().message("No se encuentra el Chofer codExterno=" + codExterno).build();
        }
        return r.get();
    }
    
    @Override
    public Chofer add(Chofer chofer) throws FoundException, BusinessException {
        // Verificar si existe por codExterno
        if (choferDAO.findOneByCodExterno(chofer.getCodExterno()).isPresent()) {
            throw FoundException.builder().message("Ya existe un Chofer con codExterno=" + chofer.getCodExterno()).build();
        }
        // Verificar si existe por documento
        if (chofer.getDocumento() != null && choferDAO.findOneByDocumento(chofer.getDocumento()).isPresent()) {
            throw FoundException.builder().message("Ya existe un Chofer con documento=" + chofer.getDocumento()).build();
        }

        try {
            return choferDAO.save(chofer);
        } catch (Exception e) {
            log.error(e.getMessage(), e);
            throw BusinessException.builder().ex(e).build();
        }
    }

    @Override
    public Chofer update(Chofer chofer) throws NotFoundException, BusinessException {
        load(chofer.getId());
        try {
            return choferDAO.save(chofer);
        } catch (Exception e) {
            log.error(e.getMessage(), e);
            throw BusinessException.builder().ex(e).build();
        }
    }

    @Override
    public void delete(long id) throws NotFoundException, BusinessException {
        load(id);
        try {
            choferDAO.deleteById(id);
        } catch (Exception e) {
            log.error(e.getMessage(), e);
            throw BusinessException.builder().ex(e).build();
        }
    }

    @Override
    public Chofer save(Chofer chofer) throws BusinessException {
        try {
            return choferDAO.save(chofer);
        } catch (Exception e) {
            throw new BusinessException(e);
        }
    }

    @Override
    public Chofer loadByDocumento(String documento) throws NotFoundException, BusinessException {
        Optional<Chofer> r;
        try {
            r = choferDAO.findOneByDocumento(documento);
        } catch (Exception e) {
            log.error(e.getMessage(), e);
            throw BusinessException.builder().ex(e).build();
        }
        if (r.isEmpty()) {
            throw NotFoundException.builder().message("No se encuentra el Chofer con documento=" + documento).build();
        }
        return r.get();
    }
}