package ar.edu.iua.iw3.model;

import java.io.Serializable;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class FlowStartDTO implements Serializable {
    private static final long serialVersionUID = 1L;
    
    private Integer numeroOrden;
    private String passwordActivacion;
}