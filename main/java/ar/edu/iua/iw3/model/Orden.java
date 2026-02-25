package ar.edu.iua.iw3.model;

import java.io.Serializable;
import java.util.Date;
import java.util.List;

import com.fasterxml.jackson.annotation.JsonFormat;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;

import ar.edu.iua.iw3.util.CamionJsonDeserializer;
import ar.edu.iua.iw3.util.ChoferJsonDeserializer;
import ar.edu.iua.iw3.util.ClienteJsonDeserializer;
import ar.edu.iua.iw3.util.ProductoJsonDeserializer;
import jakarta.persistence.CascadeType;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.OneToMany;
import jakarta.persistence.Table;
import jakarta.persistence.Temporal;
import jakarta.persistence.TemporalType;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Entity
@Table(name = "ordenes")
@AllArgsConstructor
@NoArgsConstructor
@Getter
@Setter
public class Orden implements Serializable {

	private static final long serialVersionUID = 1L;
	
	@Column(columnDefinition = "boolean default false")
	private boolean alarmaTemperaturaEnviada;
	@Column(columnDefinition = "boolean default true")
	private boolean alarmaTemperaturaAceptada; 
	
	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	private Long id;

	@OneToMany(mappedBy = "orden", cascade = CascadeType.ALL, orphanRemoval = true)
    @JsonIgnore 
    private List<DetalleCarga> detalles;

	@Column(unique = true, nullable = false)
	private Integer numeroOrden;

	@Enumerated(EnumType.ORDINAL) 
	@Column(nullable = false)
	private EstadoOrden estado = EstadoOrden.ESTADO_1_PENDIENTE_PESAJE_INICIAL;
	
	@ManyToOne
	@JoinColumn(name = "id_camion", nullable = false)
    @JsonDeserialize(using = CamionJsonDeserializer.class) 
	private Camion camion; 

	@ManyToOne
	@JoinColumn(name = "id_chofer", nullable = false)
    @JsonDeserialize(using = ChoferJsonDeserializer.class) 
	private Chofer chofer;

	@ManyToOne
	@JoinColumn(name = "id_cliente", nullable = false)
    @JsonDeserialize(using = ClienteJsonDeserializer.class) 
	private Cliente cliente;

	@ManyToOne
	@JoinColumn(name = "id_producto", nullable = false)
    @JsonDeserialize(using = ProductoJsonDeserializer.class) 
	private Producto producto;

	// Valores Base y Fechas de Proceso
@JsonFormat(shape = JsonFormat.Shape.STRING, pattern = "yyyy-MM-dd'T'HH:mm:ss.SSSXXX")
@Temporal(TemporalType.TIMESTAMP)
private Date fechaCargaPrevista;
	
	private Double preset; 
	
	// Fechas de Proceso 
	@Temporal(TemporalType.TIMESTAMP)
	private Date fechaRecepcionInicial;
	
	@Temporal(TemporalType.TIMESTAMP)
	private Date fechaPesajeInicial;
	
	@Temporal(TemporalType.TIMESTAMP)
	private Date fechaInicioCarga;
	
	@Temporal(TemporalType.TIMESTAMP)
	private Date fechaFinCarga;
	
	@Temporal(TemporalType.TIMESTAMP)
	private Date fechaPesajeFinal;

	// Datos del proceso (Estado 2)
	private Double pesajeInicial; 
	private Double pesajeFinal;
	private String passwordActivacion; 
	
	// Últimos valores
	private Double ultimaMasaAcumulada;
	private Double ultimaDensidad;
	private Double ultimaTemperatura;
	private Double ultimoCaudal;
	
	@Temporal(TemporalType.TIMESTAMP)
	private Date estampaTiempoUltimoDato;
}