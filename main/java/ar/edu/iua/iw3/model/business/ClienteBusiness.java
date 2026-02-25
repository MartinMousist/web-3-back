package ar.edu.iua.iw3.model.business;

import java.util.Optional;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import ar.edu.iua.iw3.model.Cliente;
import ar.edu.iua.iw3.model.persistence.ClienteRepository;
import lombok.extern.slf4j.Slf4j;

@Service
@Slf4j
public class ClienteBusiness implements IClienteBusiness {

    @Autowired
    private ClienteRepository clienteDAO;

    @Override
    public Cliente load(long id) throws NotFoundException, BusinessException {
        Optional<Cliente> r;
        try {
            r = clienteDAO.findById(id);
        } catch (Exception e) {
            log.error(e.getMessage(), e);
            throw BusinessException.builder().ex(e).build();
        }
        if (r.isEmpty()) {
            throw NotFoundException.builder().message("No se encuentra el Cliente id=" + id).build();
        }
        return r.get();
    }

    @Override
    public Cliente load(String codExterno) throws NotFoundException, BusinessException {
        Optional<Cliente> r;
        try {
            r = clienteDAO.findOneByCodExterno(codExterno);
        } catch (Exception e) {
            log.error(e.getMessage(), e);
            throw BusinessException.builder().ex(e).build();
        }
        if (r.isEmpty()) {
            throw NotFoundException.builder().message("No se encuentra el Cliente codExterno=" + codExterno).build();
        }
        return r.get();
    }

    @Override
    public Cliente add(Cliente cliente) throws FoundException, BusinessException {
        // Verificar si existe por codExterno
        if (clienteDAO.findOneByCodExterno(cliente.getCodExterno()).isPresent()) {
            throw FoundException.builder().message("Ya existe un Cliente con codExterno=" + cliente.getCodExterno()).build();
        }
        
        try {
            return clienteDAO.save(cliente);
        } catch (Exception e) {
            log.error(e.getMessage(), e);
            throw BusinessException.builder().ex(e).build();
        }
    }

    @Override
    public Cliente update(Cliente cliente) throws NotFoundException, BusinessException {
        load(cliente.getId());
        try {
            return clienteDAO.save(cliente);
        } catch (Exception e) {
            log.error(e.getMessage(), e);
            throw BusinessException.builder().ex(e).build();
        }
    }
    
    @Override
    public void delete(long id) throws NotFoundException, BusinessException {
        load(id);
        try {
             clienteDAO.deleteById(id);
        } catch (Exception e) {
            log.error(e.getMessage(), e);
            throw BusinessException.builder().ex(e).build();
        }
    }

    @Override
    public Cliente save(Cliente cliente) throws BusinessException {
        try {
            return clienteDAO.save(cliente);
        } catch (Exception e) {
            throw new BusinessException(e);
        }
    }

    @Override
    public Cliente loadByRazonSocial(String razonSocial) throws NotFoundException, BusinessException {
        Optional<Cliente> r;
        try {
            r = clienteDAO.findOneByRazonSocial(razonSocial);
        } catch (Exception e) {
            log.error(e.getMessage(), e);
            throw BusinessException.builder().ex(e).build();
        }
        if (r.isEmpty()) {
            throw NotFoundException.builder().message("No se encuentra el Cliente con razón social=" + razonSocial).build();
        }
        return r.get();
    }
}