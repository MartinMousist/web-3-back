package ar.edu.iua.iw3.model.business;

import ar.edu.iua.iw3.model.Cliente;

public interface IClienteBusiness {
    Cliente load(long id) throws NotFoundException, BusinessException;
    Cliente load(String codExterno) throws NotFoundException, BusinessException;
    Cliente add(Cliente cliente) throws FoundException, BusinessException;
    Cliente update(Cliente cliente) throws NotFoundException, BusinessException;
    void delete(long id) throws NotFoundException, BusinessException;
    Cliente save(Cliente cliente) throws BusinessException;
    Cliente loadByRazonSocial(String razonSocial) throws NotFoundException, BusinessException;
}