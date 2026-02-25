package ar.edu.iua.iw3.model;

import java.io.Serializable;
import lombok.Builder;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
@Builder
public class ConciliacionDTO implements Serializable {
    
    private static final long serialVersionUID = 1L;

    // Datos originales de la Orden
    private int numeroOrden;
    private double pesajeInicial;
    private double pesajeFinal;
    private Double productoCargado; 

    // Valores Calculados
    private double netoBalanza; // Pesaje final - Pesaje inicial
    private double diferenciaBalanzaCaudalimetro; // Neto por balanza - Producto cargado
    
    // Promedios
    private Double promedioTemperatura;
    private Double promedioDensidad;
    private Double promedioCaudal;
}