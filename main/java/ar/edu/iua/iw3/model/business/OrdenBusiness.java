package ar.edu.iua.iw3.model.business;

import java.util.Date;
import java.util.Optional;
import java.util.Random;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import ar.edu.iua.iw3.model.Camion;
import ar.edu.iua.iw3.model.Chofer;
import ar.edu.iua.iw3.model.Cliente;
import ar.edu.iua.iw3.model.ConciliacionDTO;
import ar.edu.iua.iw3.model.DetalleCarga;
import ar.edu.iua.iw3.model.DetalleCargaDTO;
import ar.edu.iua.iw3.model.EstadoOrden;
import ar.edu.iua.iw3.model.Orden;
import ar.edu.iua.iw3.model.Producto;
import ar.edu.iua.iw3.model.persistence.DetalleCargaRepository;
import ar.edu.iua.iw3.model.persistence.OrdenRepository;
import ar.edu.iua.iw3.util.EmailBusiness;
import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import lombok.extern.slf4j.Slf4j;

@Service
@Slf4j
public class OrdenBusiness implements IOrdenBusiness {

    @Autowired
    private OrdenRepository ordenDAO;
    
    // Dependencias inyectadas
    @Autowired 
    private ICamionBusiness camionBusiness;
    @Autowired 
    private IChoferBusiness choferBusiness;
    @Autowired 
    private IClienteBusiness clienteBusiness;
    @Autowired 
    private IProductoBusiness productoBusiness;
    
    // Métodos load
    @Override
    public Orden load(long id) throws NotFoundException, BusinessException {
        Optional<Orden> r;
        try {
            r = ordenDAO.findById(id);
        } catch (Exception e) {
            log.error(e.getMessage(), e);
            throw BusinessException.builder().ex(e).build();
        }
        if (r.isEmpty()) {
            throw NotFoundException.builder().message("No se encuentra la Orden id=" + id).build();
        }
        return r.get();
    }

    @Override
    public Orden load(int numeroOrden) throws NotFoundException, BusinessException {
        Optional<Orden> r;
        try {
            r = ordenDAO.findOneByNumeroOrden(numeroOrden);
        } catch (Exception e) {
            log.error(e.getMessage(), e);
            throw BusinessException.builder().ex(e).build();
        }
        if (r.isEmpty()) {
            throw NotFoundException.builder().message("No se encuentra la Orden Nro=" + numeroOrden).build();
        }
        return r.get();
    }
    
    // --- LÓGICA DE CARGA O CREACIÓN ON-DEMAND ---

    private Camion loadOrCreateCamion(Camion camion) throws BusinessException, FoundException {
        // Si trae ID, cargamos por ID (lógica antigua)
        if (camion.getId() != null && camion.getId() > 0) {
            try {
                return camionBusiness.load(camion.getId());
            } catch (NotFoundException e) {
                throw BusinessException.builder().message("Camión ID=" + camion.getId() + " no encontrado.").build();
            }
        }
        
        // Si no trae ID, intentamos cargar por Patente (única)
        if (camion.getPatente() != null) {
            try {
                return camionBusiness.loadByPatente(camion.getPatente());
            } catch (NotFoundException e) {
                // Si no existe, lo creamos
                if (camion.getCodExterno() == null) {
                    camion.setCodExterno(camion.getPatente());
                }
                return camionBusiness.add(camion);
            }
        }
        throw BusinessException.builder().message("Datos insuficientes para Camión (falta Patente).").build();
    }

    private Chofer loadOrCreateChofer(Chofer chofer) throws BusinessException, FoundException {
        if (chofer.getId() != null && chofer.getId() > 0) {
            try {
                return choferBusiness.load(chofer.getId());
            } catch (NotFoundException e) {
                throw BusinessException.builder().message("Chofer ID=" + chofer.getId() + " no encontrado.").build();
            }
        }
        
        // Intentamos cargar por Documento (único)
        if (chofer.getDocumento() != null) {
            try {
                return choferBusiness.loadByDocumento(chofer.getDocumento());
            } catch (NotFoundException e) {
                // Si no existe, lo creamos
                if (chofer.getCodExterno() == null) {
                    chofer.setCodExterno(chofer.getDocumento());
                }
                return choferBusiness.add(chofer);
            }
        }
        throw BusinessException.builder().message("Datos insuficientes para Chofer (falta Documento).").build();
    }

    private Cliente loadOrCreateCliente(Cliente cliente) throws BusinessException, FoundException {
        if (cliente.getId() != null && cliente.getId() > 0) {
            try {
                return clienteBusiness.load(cliente.getId());
            } catch (NotFoundException e) {
                throw BusinessException.builder().message("Cliente ID=" + cliente.getId() + " no encontrado.").build();
            }
        }
        
        // Intentamos cargar por Razón Social
        if (cliente.getRazonSocial() != null && !cliente.getRazonSocial().trim().isEmpty()) {
            String razonSocialKey = cliente.getRazonSocial().trim(); // Usamos el valor limpio para buscar y generar
            
            try {
                return clienteBusiness.loadByRazonSocial(razonSocialKey);
            } catch (NotFoundException e) {
                // Si no existe, lo creamos
                if (cliente.getCodExterno() == null || cliente.getCodExterno().isEmpty()) {
                    String cleanRazonSocial = razonSocialKey.replaceAll("\\s+", "");
                    int length = cleanRazonSocial.length();
                    int prefixLength = Math.min(length, 15);
                    
                    cliente.setCodExterno(cleanRazonSocial.substring(0, prefixLength) + "-" + System.currentTimeMillis());
                }
                return clienteBusiness.add(cliente);
            }
        }
        throw BusinessException.builder().message("Datos insuficientes para Cliente (falta Razón Social y ID).").build();
    }

    private Producto loadOrCreateProducto(Producto producto) throws BusinessException, FoundException {
        if (producto.getId() != null && producto.getId() > 0) {
            try {
                return productoBusiness.load(producto.getId());
            } catch (NotFoundException e) {
                throw BusinessException.builder().message("Producto ID=" + producto.getId() + " no encontrado.").build();
            }
        }
        // Intentamos cargar por Nombre 
        if (producto.getNombre() != null) {
            try {
                return productoBusiness.loadByNombre(producto.getNombre());
            } catch (NotFoundException e) {
                // Si no existe, lo creamos
                if (producto.getCodExterno() == null) {
                    producto.setCodExterno(producto.getNombre());
                }
                return productoBusiness.add(producto);
            }
        }
        throw BusinessException.builder().message("Datos insuficientes para Producto (falta Nombre).").build();
    }

    // Método Punto 1: Recepción de datos base
    @Override
    public Orden add(Orden orden) throws FoundException, BusinessException {
        if (ordenDAO.findOneByNumeroOrden(orden.getNumeroOrden()).isPresent()) {
            throw FoundException.builder().message("La Orden Nro=" + orden.getNumeroOrden() + " ya existe.").build();
        }
        try {
            // Usamos load/add en el Business auxiliar.
            // si ID es null, intenta cargar por campos únicos y la crea si es necesario.
            orden.setCamion(loadOrCreateCamion(orden.getCamion()));
            orden.setChofer(loadOrCreateChofer(orden.getChofer()));
            orden.setCliente(loadOrCreateCliente(orden.getCliente()));
            orden.setProducto(loadOrCreateProducto(orden.getProducto())); 
        } catch (FoundException e) {
            throw e;
        }

        // Setear estado inicial y fecha de recepción
        orden.setEstado(EstadoOrden.ESTADO_1_PENDIENTE_PESAJE_INICIAL);
        orden.setFechaRecepcionInicial(new Date());

        try {
            return ordenDAO.save(orden);
        } catch (Exception e) {
            log.error(e.getMessage(), e);
            throw BusinessException.builder().ex(e).build();
        }
    }
    
    // Método Punto 2: Registro de tara
    @Override
    public Orden registerInitialWeighing(int numeroOrden, double pesajeInicial) 
            throws NotFoundException, BusinessException {
        
        Orden orden = load(numeroOrden);

        if (orden.getEstado() != EstadoOrden.ESTADO_1_PENDIENTE_PESAJE_INICIAL) {
            throw BusinessException.builder()
                .message("La Orden Nro=" + numeroOrden + " no está en estado 'Pendiente de pesaje inicial'. Estado actual: " + orden.getEstado().getDescripcion())
                .build();
        }

        orden.setPesajeInicial(pesajeInicial);
        orden.setFechaPesajeInicial(new Date());
        
        Random random = new Random();
        int password = 10000 + random.nextInt(90000);
        orden.setPasswordActivacion(String.valueOf(password));

        orden.setEstado(EstadoOrden.ESTADO_2_CON_PESAJE_INICIAL_REGISTRADO);

        try {
            log.info("Orden {} pasa a Estado 2. Password: {}", numeroOrden, password);
            return ordenDAO.save(orden);
        } catch (Exception e) {
            log.error(e.getMessage(), e);
            throw BusinessException.builder().ex(e).build();
        }
    }


    @Autowired
    private DetalleCargaRepository detalleCargaDAO;

    // --- IMPLEMENTACIÓN DEL PUNTO 3 UNIFICADO ---
    @Value("${alarma.temperatura.umbral}")
    private double tempUmbral;

    @Value("${alarma.temperatura.destinatario}")
    private String tempDestinatario;

    @Autowired
    private EmailBusiness emailBusiness;

    @Override
    public Orden receiveRealTimeData(DetalleCargaDTO data) throws NotFoundException, BusinessException {
        log.info("Recibiendo datos en tiempo real para Orden Nro={}", data.getNumeroOrden());
        Orden orden = load(data.getNumeroOrden());
        
        // Validar estado: Debe ser Estado 2
        if (orden.getEstado() != EstadoOrden.ESTADO_2_CON_PESAJE_INICIAL_REGISTRADO) {
            log.error("Orden {} en estado incorrecto: {}", data.getNumeroOrden(), orden.getEstado());
            throw BusinessException.builder()
                .message("La Orden Nro=" + data.getNumeroOrden() + " no está lista para iniciar la carga (Estado 2). Estado actual: " + orden.getEstado().getDescripcion())
                .build();
        }

        // El dispositivo debe enviar la contraseña en el DTO
        if (data.getPasswordActivacion() == null) {
            log.warn("Intento de carga sin contraseña para Orden {}", data.getNumeroOrden());
            throw BusinessException.builder().message("La petición de flujo continuo requiere 'passwordActivacion'.").build();
        }

        // Verificar Contraseña
        if (!orden.getPasswordActivacion().equals(data.getPasswordActivacion())) {
            log.error("Contraseña incorrecta para Orden {}", data.getNumeroOrden());
            throw BusinessException.builder().message("Contraseña de activación incorrecta.").build();
        }
        
        boolean datosValidos = isRealTimeDataValid(orden, data);

        if (datosValidos) {
            log.debug("Datos válidos para Orden {}. Actualizando cabecera y persistiendo detalle.", data.getNumeroOrden());
            // Procesar datos: Actualizar cabecera y persistir detalle
            updateOrderHeader(orden, data);
            persistDetail(orden, data);

            // --- Lógica de Alarma de Temperatura ---
            log.trace("Verificando alarma: Temp recibida {}°C / Umbral {}°C", data.getTemperatura(), tempUmbral);
            
            if (data.getTemperatura() > tempUmbral) {
                log.info("¡Umbral superado en Orden {}! Temp: {}°C", data.getNumeroOrden(), data.getTemperatura());
                
                // Solo se envía si la alarma no fue enviada aún O si la anterior ya fue aceptada
                if (!orden.isAlarmaTemperaturaEnviada() || orden.isAlarmaTemperaturaAceptada()) {
                    log.info("Enviando correo de alerta a {}", tempDestinatario);
                    try {
                        emailBusiness.sendSimpleMessage(
                            tempDestinatario, 
                            "ALERTA: Umbral de temperatura excedido", 
                            "La orden " + orden.getNumeroOrden() + " registró " + data.getTemperatura() + "°C"
                        );
                        // Actualizar flags para evitar reenvíos hasta la aceptación
                        orden.setAlarmaTemperaturaEnviada(true);
                        orden.setAlarmaTemperaturaAceptada(false);
                        log.debug("Flags de alarma actualizados: Enviada=true, Aceptada=false");
                    } catch (Exception e) {
                        log.error("Error al enviar correo de alarma: {}", e.getMessage());
                    }
                } else {
                    log.debug("Alarma ya enviada y pendiente de aceptación para Orden {}. No se reenvía correo.", data.getNumeroOrden());
                }
            }
            
            try {
                log.debug("Guardando cambios de la Orden {} en base de datos.", data.getNumeroOrden());
                return ordenDAO.save(orden);
            } catch (Exception e) {
                log.error("Error al guardar la orden actualizada: {}", e.getMessage(), e);
                throw BusinessException.builder().ex(e).build();
            }

        } else {
            log.warn("Datos recibidos para Orden {} descartados por no ser válidos (Caudal/Masa <= 0 o Masa menor a la anterior).", orden.getNumeroOrden());
            return orden;
        }
    }
    
    private boolean isRealTimeDataValid(Orden orden, DetalleCargaDTO data) {
        if (data.getCaudal() == null || data.getCaudal() <= 0) {
            log.trace("Dato inválido: Caudal nulo o <= 0");
            return false; 
        }
        
        if (data.getMasaAcumulada() == null || data.getMasaAcumulada() <= 0) {
            log.trace("Dato inválido: Masa acumulada nula o <= 0");
            return false; 
        }
        
        if (orden.getUltimaMasaAcumulada() != null && data.getMasaAcumulada() < orden.getUltimaMasaAcumulada()) {
            log.warn("Dato inválido: Masa acumulada {} es menor que la anterior {}", data.getMasaAcumulada(), orden.getUltimaMasaAcumulada());
            return false; 
        }
        
        return true;
    }

    private void updateOrderHeader(Orden orden, DetalleCargaDTO data) {
        Date now = new Date();
        if (orden.getFechaInicioCarga() == null) {
            orden.setFechaInicioCarga(now);
        }
        orden.setUltimaMasaAcumulada(data.getMasaAcumulada());
        orden.setUltimaDensidad(data.getDensidad());
        orden.setUltimaTemperatura(data.getTemperatura());
        orden.setUltimoCaudal(data.getCaudal());
        orden.setEstampaTiempoUltimoDato(now);
    }
    
    private void persistDetail(Orden orden, DetalleCargaDTO data) throws BusinessException {
        DetalleCarga detalle = new DetalleCarga();
        detalle.setOrden(orden);
        detalle.setMasaAcumulada(data.getMasaAcumulada());
        detalle.setDensidad(data.getDensidad());
        detalle.setTemperatura(data.getTemperatura());
        detalle.setCaudal(data.getCaudal());
        detalle.setEstampaTiempo(orden.getEstampaTiempoUltimoDato());

        try {
            detalleCargaDAO.save(detalle);
        } catch (Exception e) {
            log.error("Error al guardar detalle de carga: {}", e.getMessage(), e);
            throw BusinessException.builder().message("Fallo al persistir detalle de carga.").build();
        }
    }

    // Implementación del Punto 4: Cierre de la Orden
    @Override
    public Orden closeOrder(int numeroOrden) throws NotFoundException, BusinessException {
        
        Orden orden = load(numeroOrden); // Verifica si la orden existe

        if (orden.getEstado() != EstadoOrden.ESTADO_2_CON_PESAJE_INICIAL_REGISTRADO) {
            throw BusinessException.builder()
                .message("La Orden Nro=" + numeroOrden + " no está activa para ser cerrada. Estado actual: " + orden.getEstado().getDescripcion())
                .build();
        }

        orden.setFechaFinCarga(new Date()); 
        orden.setEstado(EstadoOrden.ESTADO_3_CERRADA_PARA_CARGA);

        try {
            log.info("Orden {} pasa a Estado 3: Cerrada para carga.", numeroOrden);
            return ordenDAO.save(orden);
        } catch (Exception e) {
            log.error("Error al cerrar la orden: {}", e.getMessage(), e);
            throw BusinessException.builder().ex(e).build();
        }
    }

    @PersistenceContext // Inyección para consultas de BD avanzadas como los promedios
    private EntityManager entityManager;

    // --- PUNTO 5 - PARTE 1: Registrar Pesaje Final (PUT) ---
    @Override
    public Orden registerFinalWeighing(int numeroOrden, double pesajeFinal) throws NotFoundException, BusinessException {
        Orden orden = load(numeroOrden);

        if (orden.getEstado() != EstadoOrden.ESTADO_3_CERRADA_PARA_CARGA) {
            throw BusinessException.builder()
                .message("La Orden Nro=" + numeroOrden + " no está cerrada. Estado actual: " + orden.getEstado().getDescripcion())
                .build();
        }
        
        orden.setPesajeFinal(pesajeFinal);
        orden.setFechaPesajeFinal(new Date());
        orden.setEstado(EstadoOrden.ESTADO_4_FINALIZADA);

        try {
            log.info("Orden {} pasa a Estado 4: Finalizada. Pesaje final: {}", numeroOrden, pesajeFinal);
            return ordenDAO.save(orden);
        } catch (Exception e) {
            log.error("Error al registrar pesaje final: {}", e.getMessage(), e);
            throw BusinessException.builder().ex(e).build();
        }
    }

    // --- PUNTO 5 - PARTE 2: Obtener Conciliación (GET) ---
    @Override
    public ConciliacionDTO getConciliacion(int numeroOrden) throws NotFoundException, BusinessException {
        Orden orden = load(numeroOrden);
        
        if (orden.getEstado() != EstadoOrden.ESTADO_4_FINALIZADA) {
            throw BusinessException.builder()
                .message("La Orden Nro=" + numeroOrden + " no está finalizada. Estado actual: " + orden.getEstado().getDescripcion())
                .build();
        }
        
        if (orden.getPesajeInicial() == null || orden.getPesajeFinal() == null || orden.getUltimaMasaAcumulada() == null) {
             throw BusinessException.builder().message("Faltan datos de pesaje o carga para la conciliación.").build();
        }
        
        // Cálculo de Neto y Diferencia
        double netoBalanza = orden.getPesajeFinal() - orden.getPesajeInicial();
        double diferenciaBalanzaCaudalimetro = netoBalanza - orden.getUltimaMasaAcumulada();

        // Cálculo de Promedios (Usando el EntityManager)
        Object[] promedios = calculateAverages(orden.getId());
        
        // Construir DTO
        return ConciliacionDTO.builder()
                .numeroOrden(numeroOrden)
                .pesajeInicial(orden.getPesajeInicial())
                .pesajeFinal(orden.getPesajeFinal())
                .productoCargado(orden.getUltimaMasaAcumulada())
                .netoBalanza(netoBalanza)
                .diferenciaBalanzaCaudalimetro(diferenciaBalanzaCaudalimetro)
                .promedioTemperatura((Double) promedios[0])
                .promedioDensidad((Double) promedios[1])
                .promedioCaudal((Double) promedios[2])
                .build();
    }
    
    // Método para calcular promedios de detalle
    private Object[] calculateAverages(Long ordenId) throws BusinessException {
        try {
            // Consulta nativa para obtener los promedios (AVG)
            String sql = "SELECT AVG(temperatura), AVG(densidad), AVG(caudal) FROM detalle_cargas WHERE id_orden = :ordenId";
            
            Object[] result = (Object[]) entityManager.createNativeQuery(sql)
                .setParameter("ordenId", ordenId)
                .getSingleResult();

            // Casteamos los resultados (result[0]=Temp, result[1]=Dens, result[2]=Caudal)
            Double avgTemp = result[0] != null ? ((Number) result[0]).doubleValue() : null;
            Double avgDens = result[1] != null ? ((Number) result[1]).doubleValue() : null;
            Double avgCaudal = result[2] != null ? ((Number) result[2]).doubleValue() : null;

            return new Object[]{avgTemp, avgDens, avgCaudal};
            
        } catch (Exception e) {
            log.error("Error al calcular promedios para la orden {}: {}", ordenId, e.getMessage());
            throw BusinessException.builder().message("Error calculando promedios de detalle.").build();
        }
    }


    @Override
    public void delete(int numeroOrden) throws NotFoundException, BusinessException {
        // 1. Buscamos la orden por número de orden para obtener su ID real
        Orden orden = load(numeroOrden);
        
        try {
            // 2. Eliminamos usando el ID de la orden cargada
            ordenDAO.deleteById(orden.getId());
        } catch (Exception e) {
            log.error(e.getMessage(), e);
            throw BusinessException.builder().ex(e).build();
        }
    }

    @Override
    public void aceptarAlarmaTemperatura(int numeroOrden) throws NotFoundException, BusinessException {
        Orden orden = load(numeroOrden);
        orden.setAlarmaTemperaturaAceptada(true);
        ordenDAO.save(orden);
    }


    @Override
    public java.util.List<Orden> list() throws BusinessException {
        try {
            return ordenDAO.findAll();
        } catch (Exception e) {
            log.error(e.getMessage(), e);
            throw BusinessException.builder().ex(e).build();
        }
    }
}
