package ar.edu.iua.iw3.model.business;
import java.util.List;

import ar.edu.iua.iw3.model.ConciliacionDTO;
import ar.edu.iua.iw3.model.DetalleCargaDTO;
import ar.edu.iua.iw3.model.Orden;

public interface IOrdenBusiness {
    // --- PUNTO 1: RECEPCION DE DATOS BASE ---
    public Orden load(long id) throws NotFoundException, BusinessException;
    public Orden load(int numeroOrden) throws NotFoundException, BusinessException;
    public Orden add(Orden orden) throws FoundException, BusinessException;

    // --- PUNTO 2: REGISTRO DE TARA ---
    public Orden registerInitialWeighing(int numeroOrden, double pesajeInicial) throws NotFoundException, BusinessException;

    // --- PUNTO 3: RECEPCIÓN DE DATOS CONTINUOS ---
    public Orden receiveRealTimeData(DetalleCargaDTO data) throws NotFoundException, BusinessException;

    // --- PUNTO 4: CIERRE DE ORDEN ---
    public Orden closeOrder(int numeroOrden) throws NotFoundException, BusinessException;

    // --- PUNTO 5: REGISTRO DE PESAJE FINAL ---
    public Orden registerFinalWeighing(int numeroOrden, double pesajeFinal) throws NotFoundException, BusinessException;

    // --- PUNTO 5: CONCILIACIÓN ---
    public ConciliacionDTO getConciliacion(int numeroOrden) throws NotFoundException, BusinessException;


    public void delete(int numeroOrden) throws NotFoundException, BusinessException;

    public void aceptarAlarmaTemperatura(int numeroOrden) throws NotFoundException, BusinessException;

    public List<Orden> list() throws BusinessException;
}