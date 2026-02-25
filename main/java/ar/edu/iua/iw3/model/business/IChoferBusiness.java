package ar.edu.iua.iw3.model.business;

import ar.edu.iua.iw3.model.Chofer;

public interface IChoferBusiness {
    Chofer load(long id) throws NotFoundException, BusinessException;
    Chofer load(String codExterno) throws NotFoundException, BusinessException;
    Chofer add(Chofer chofer) throws FoundException, BusinessException;
    Chofer update(Chofer chofer) throws NotFoundException, BusinessException;
    void delete(long id) throws NotFoundException, BusinessException;
    Chofer save(Chofer chofer) throws BusinessException;
    Chofer loadByDocumento(String documento) throws NotFoundException, BusinessException;
}