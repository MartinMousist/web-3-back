package ar.edu.iua.iw3.model.business;

import java.util.Optional;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import ar.edu.iua.iw3.model.Producto;
import ar.edu.iua.iw3.model.persistence.ProductoRepository;
import lombok.extern.slf4j.Slf4j;

@Service
@Slf4j
public class ProductoBusiness implements IProductoBusiness {

    @Autowired
    private ProductoRepository productoDAO;

    @Override
    public Producto load(long id) throws NotFoundException, BusinessException {
        Optional<Producto> r;
        try {
            r = productoDAO.findById(id);
        } catch (Exception e) {
            log.error(e.getMessage(), e);
            throw BusinessException.builder().ex(e).build();
        }
        if (r.isEmpty()) {
            throw NotFoundException.builder().message("No se encuentra el Producto id=" + id).build();
        }
        return r.get();
    }

    @Override
    public Producto load(String codExterno) throws NotFoundException, BusinessException {
        Optional<Producto> r;
        try {
            r = productoDAO.findOneByCodExterno(codExterno);
        } catch (Exception e) {
            log.error(e.getMessage(), e);
            throw BusinessException.builder().ex(e).build();
        }
        if (r.isEmpty()) {
            throw NotFoundException.builder().message("No se encuentra el Producto codExterno=" + codExterno).build();
        }
        return r.get();
    }
    
    @Override
    public Producto add(Producto producto) throws FoundException, BusinessException {
        // Verificar si existe por codExterno
        if (productoDAO.findOneByCodExterno(producto.getCodExterno()).isPresent()) {
            throw FoundException.builder().message("Ya existe un Producto con codExterno=" + producto.getCodExterno()).build();
        }
        // Verificar si existe por nombre
        if (productoDAO.findOneByNombre(producto.getNombre()).isPresent()) {
            throw FoundException.builder().message("Ya existe un Producto con nombre=" + producto.getNombre()).build();
        }

        try {
            return productoDAO.save(producto);
        } catch (Exception e) {
            log.error(e.getMessage(), e);
            throw BusinessException.builder().ex(e).build();
        }
    }

    @Override
    public Producto update(Producto producto) throws NotFoundException, BusinessException {
        load(producto.getId());
        try {
            return productoDAO.save(producto);
        } catch (Exception e) {
            log.error(e.getMessage(), e);
            throw BusinessException.builder().ex(e).build();
        }
    }
    
    @Override
    public void delete(long id) throws NotFoundException, BusinessException {
        load(id);
        try {
            productoDAO.deleteById(id);
        } catch (Exception e) {
            log.error(e.getMessage(), e);
            throw BusinessException.builder().ex(e).build();
        }
    }

    @Override
    public Producto save(Producto producto) throws BusinessException {
        try {
            return productoDAO.save(producto);
        } catch (Exception e) {
            throw BusinessException.builder().ex(e).build();
        }
    }

    @Override
    public Producto loadByNombre(String nombre) throws NotFoundException, BusinessException {
        Optional<Producto> r;
        try {
            r = productoDAO.findOneByNombre(nombre);
        } catch (Exception e) {
            log.error(e.getMessage(), e);
            throw BusinessException.builder().ex(e).build();
        }
        if (r.isEmpty()) {
            throw NotFoundException.builder().message("No se encuentra el Producto con nombre=" + nombre).build();
        }
        return r.get();
    }
}