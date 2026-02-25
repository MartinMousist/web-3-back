package ar.edu.iua.iw3.model;

import lombok.Getter;

@Getter
public enum EstadoOrden {
    ESTADO_1_PENDIENTE_PESAJE_INICIAL(1, "Pendiente de pesaje inicial"), 
    ESTADO_2_CON_PESAJE_INICIAL_REGISTRADO(2, "Con pesaje inicial registrado"),
    ESTADO_3_CERRADA_PARA_CARGA(3, "Cerrada para carga"),
    ESTADO_4_FINALIZADA(4, "Finalizada");

    private int id;
    private String descripcion;

    EstadoOrden(int id, String descripcion) {
        this.id = id;
        this.descripcion = descripcion;
    }
}