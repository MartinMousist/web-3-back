package ar.edu.iua.iw3.controllers;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import ar.edu.iua.iw3.model.ConciliacionDTO;
import ar.edu.iua.iw3.model.DetalleCargaDTO;
import ar.edu.iua.iw3.model.Orden;
import ar.edu.iua.iw3.model.business.BusinessException;
import ar.edu.iua.iw3.model.business.FoundException;
import ar.edu.iua.iw3.model.business.IOrdenBusiness;
import ar.edu.iua.iw3.model.business.NotFoundException;
import ar.edu.iua.iw3.util.IStandartResponseBusiness;
import io.swagger.v3.oas.annotations.tags.Tag;


@RestController
@RequestMapping(Constants.URL_ORDENES)
@Tag(description = "API para la administración de Órdenes de Carga", name = "Ordenes")
public class OrdenRestController extends BaseRestController {

    @Autowired
    private IOrdenBusiness ordenBusiness; 
    @Autowired
    private IStandartResponseBusiness response;

    // PUNTO 1: RECEPCIÓN DE DATOS / CREAR ORDEN (POST)
    // Crea la orden en Estado 1: Pendiente de pesaje inicial.
    // URL: POST /api/v1/ordenes
    @PostMapping(value = "")
    public ResponseEntity<?> add(@RequestBody Orden orden) {
        try {
            Orden result = ordenBusiness.add(orden);
            HttpHeaders responseHeaders = new HttpHeaders();  
            // Retorna la URL del nuevo recurso creado
            responseHeaders.set("location", "/api/v1/ordenes/" + result.getNumeroOrden());
            return new ResponseEntity<>(responseHeaders, HttpStatus.CREATED);
            
        } catch (BusinessException e) { // Para fallos de lógica o BD
            return new ResponseEntity<>(response.build(HttpStatus.INTERNAL_SERVER_ERROR, e, e.getMessage()), HttpStatus.INTERNAL_SERVER_ERROR);
        } catch (FoundException e) { // Si la orden ya existe
            return new ResponseEntity<>(response.build(HttpStatus.CONFLICT, e, e.getMessage()), HttpStatus.CONFLICT);
        }
    }

    // --- PUNTO 2: REGISTRO DE PESAJE INICIAL (PUT) ---
    // Pasa la orden a Estado 2: Con pesaje inicial registrado, y genera la contraseña.
    // URL: PUT /api/v1/ordenes/{numeroOrden}/tara
    @PutMapping(value = "/{numeroOrden}/tara")
    public ResponseEntity<?> registerInitialWeighing(
        @PathVariable int numeroOrden, 
        @RequestParam double tara
    ) {
        try {
            Orden result = ordenBusiness.registerInitialWeighing(numeroOrden, tara); // Pasa a Estado 2
            Map<String, String> responseBody = new HashMap<>();
            responseBody.put("numeroOrden", String.valueOf(result.getNumeroOrden()));
            responseBody.put("estado", result.getEstado().getDescripcion());
            responseBody.put("passwordActivacion", result.getPasswordActivacion()); // Devuelve la contraseña de activación
            return new ResponseEntity<>(responseBody, HttpStatus.OK);
            
        } catch (NotFoundException e) {
            return new ResponseEntity<>(response.build(HttpStatus.NOT_FOUND, e, e.getMessage()), HttpStatus.NOT_FOUND);
        } catch (BusinessException e) { // Error de lógica por ej. estado incorrecto
            return new ResponseEntity<>(response.build(HttpStatus.CONFLICT, e, e.getMessage()), HttpStatus.CONFLICT);
        }
    }

    // --- UTILIDAD (no requerida en el tp): VER ESTADO ORDEN POR NÚMERO ---
    // Permite verificar el estado de la orden después de la creación/actualización.
    // URL: GET /api/v1/ordenes/{numeroOrden}
    @GetMapping(value = "/{numeroOrden}", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<?> load(@PathVariable int numeroOrden) {
        try {
            return new ResponseEntity<>(ordenBusiness.load(numeroOrden), HttpStatus.OK);
        } catch (BusinessException e) {
            return new ResponseEntity<>(response.build(HttpStatus.INTERNAL_SERVER_ERROR, e, e.getMessage()),
                    HttpStatus.INTERNAL_SERVER_ERROR);
        } catch (NotFoundException e) {
            return new ResponseEntity<>(response.build(HttpStatus.NOT_FOUND, e, e.getMessage()), HttpStatus.NOT_FOUND);
        }
    }

    // --- PUNTO 3: RECEPCIÓN DE DATOS CONTINUOS (POST) ---
    // Recibe los datos de detalle de carga en tiempo real.
    @PostMapping(value = "/flow")
    public ResponseEntity<?> receiveRealTimeData(@RequestBody DetalleCargaDTO data) {
        try {
            Orden result = ordenBusiness.receiveRealTimeData(data); // Devuelve la cabecera actualizada con los ultimos valores
            return new ResponseEntity<>(result, HttpStatus.OK);
            
        } catch (NotFoundException e) { // Contraseña invalida o no existe Orden activa
            return new ResponseEntity<>(response.build(HttpStatus.NOT_FOUND, e, e.getMessage()), HttpStatus.NOT_FOUND);
        } catch (BusinessException e) { // Orden no está en Estado 2 
            return new ResponseEntity<>(response.build(HttpStatus.CONFLICT, e, e.getMessage()), HttpStatus.CONFLICT);
        }
    }

    // --- PUNTO 4: CIERRE DE LA ORDEN (PUT) ---
    // Pasa la orden a Estado 3: Cerrada para carga, bloqueando la recepción de datos.
    // URL: PUT /api/v1/ordenes/{numeroOrden}/close
    @PutMapping(value = "/{numeroOrden}/close")
    public ResponseEntity<?> closeOrder(@PathVariable int numeroOrden) {
        try {
            Orden result = ordenBusiness.closeOrder(numeroOrden); // Pasa a Estado 3
            
            Map<String, String> responseBody = new HashMap<>();
            responseBody.put("numeroOrden", String.valueOf(result.getNumeroOrden()));
            responseBody.put("estado", result.getEstado().getDescripcion());

            return new ResponseEntity<>(responseBody, HttpStatus.OK);
            
        } catch (NotFoundException e) {
            return new ResponseEntity<>(response.build(HttpStatus.NOT_FOUND, e, e.getMessage()), HttpStatus.NOT_FOUND);
        } catch (BusinessException e) {
            return new ResponseEntity<>(response.build(HttpStatus.CONFLICT, e, e.getMessage()), HttpStatus.CONFLICT);
        }
    }

    // --- PUNTO 5 - P1: REGISTRO DE PESAJE FINAL (PUT) ---
    // Recibe el pesaje final y pasa a Estado 4.
    // URL: PUT /api/v1/ordenes/{numeroOrden}/final-weighing
    @PutMapping(value = "/{numeroOrden}/final-weighing")
    public ResponseEntity<?> registerFinalWeighing(
        @PathVariable int numeroOrden, 
        @RequestParam double pesajeFinal
    ) {
        try {
            Orden result = ordenBusiness.registerFinalWeighing(numeroOrden, pesajeFinal); // Pasa a Estado 4
            
            Map<String, String> responseBody = new HashMap<>();
            responseBody.put("numeroOrden", String.valueOf(result.getNumeroOrden()));
            responseBody.put("estado", result.getEstado().getDescripcion());

            return new ResponseEntity<>(responseBody, HttpStatus.OK);
            
        } catch (NotFoundException e) {
            return new ResponseEntity<>(response.build(HttpStatus.NOT_FOUND, e, e.getMessage()), HttpStatus.NOT_FOUND);
        } catch (BusinessException e) {
            return new ResponseEntity<>(response.build(HttpStatus.CONFLICT, e, e.getMessage()), HttpStatus.CONFLICT);
        }
    }


    // --- PUNTO 5 - P2: OBTENER CONCILIACIÓN (GET) ---
    // Devuelve los valores calculados, solo si la orden está en Estado 4.
    // URL: GET /api/v1/ordenes/{numeroOrden}/conciliacion
    @GetMapping(value = "/{numeroOrden}/conciliacion", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<?> getConciliacion(@PathVariable int numeroOrden) {
        try {
            ConciliacionDTO conciliacion = ordenBusiness.getConciliacion(numeroOrden);
            return new ResponseEntity<>(conciliacion, HttpStatus.OK);
            
        } catch (BusinessException e) { // Faltan datos para el cálculo o si no está en Estado 4.
            return new ResponseEntity<>(response.build(HttpStatus.CONFLICT, e, e.getMessage()), HttpStatus.CONFLICT);
        } catch (NotFoundException e) {
            return new ResponseEntity<>(response.build(HttpStatus.NOT_FOUND, e, e.getMessage()), HttpStatus.NOT_FOUND);
        }
    }

    @DeleteMapping(value = "/{numeroOrden}")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<?> delete(@PathVariable int numeroOrden) {
        try {
            ordenBusiness.delete(numeroOrden);
            return new ResponseEntity<>(HttpStatus.NO_CONTENT);
        } catch (NotFoundException e) {
            return new ResponseEntity<>(response.build(HttpStatus.NOT_FOUND, e, e.getMessage()), HttpStatus.NOT_FOUND);
        } catch (BusinessException e) {
            return new ResponseEntity<>(response.build(HttpStatus.INTERNAL_SERVER_ERROR, e, e.getMessage()), HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    @PutMapping(value = "/{numeroOrden}/aceptar-alarma")
    //@PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<?> aceptarAlarma(@PathVariable int numeroOrden) {
        try {
            ordenBusiness.aceptarAlarmaTemperatura(numeroOrden);
            return new ResponseEntity<>(HttpStatus.OK);
        } catch (Exception e) {
            return new ResponseEntity<>(response.build(HttpStatus.INTERNAL_SERVER_ERROR, e, e.getMessage()), HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    

@GetMapping(value = "", produces = MediaType.APPLICATION_JSON_VALUE)
public ResponseEntity<List<Orden>> list() {
    try {
        return new ResponseEntity<>(ordenBusiness.list(), HttpStatus.OK);
    } catch (BusinessException e) {
        return new ResponseEntity<>(HttpStatus.INTERNAL_SERVER_ERROR);
    }
}

    
}