package ar.edu.iua.iw3.model.business;

import ar.edu.iua.iw3.model.Producto;

public interface IProductoBusiness {
    Producto load(long id) throws NotFoundException, BusinessException;
    Producto load(String codExterno) throws NotFoundException, BusinessException;
    Producto add(Producto producto) throws FoundException, BusinessException;
    Producto update(Producto producto) throws NotFoundException, BusinessException;
    void delete(long id) throws NotFoundException, BusinessException;
    Producto save(Producto producto) throws BusinessException;
    Producto loadByNombre(String nombre) throws NotFoundException, BusinessException;
}