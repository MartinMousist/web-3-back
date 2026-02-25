package ar.edu.iua.iw3.model;

import java.io.Serializable;

import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

@Getter
@Setter
@ToString
public class DetalleCargaDTO implements Serializable {

    private static final long serialVersionUID = 1L;

    private Integer numeroOrden;

    private String passwordActivacion; 

    // Datos de detalle recibidos
    private Double masaAcumulada;   // kg
    private Double densidad;        // kg/m³
    private Double temperatura;     // °C
    private Double caudal;          // kg/h
}