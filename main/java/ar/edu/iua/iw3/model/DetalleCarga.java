package ar.edu.iua.iw3.model;

import java.io.Serializable;
import java.util.Date;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;
import jakarta.persistence.Temporal;
import jakarta.persistence.TemporalType;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Entity
@Table(name = "detalle_cargas")
@AllArgsConstructor
@NoArgsConstructor
@Getter
@Setter
public class DetalleCarga implements Serializable {

	private static final long serialVersionUID = 1L;

	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	private Long id;

	// Relación con la Orden principal
	@ManyToOne
	@JoinColumn(name = "id_orden", nullable = false)
	private Orden orden;

	// Datos de Detalle recibidos
	private Double masaAcumulada; // Masa acumulada (kg)
	private Double densidad; // Densidad (kg/m³)
	private Double temperatura; // Temperatura (°C)
	private Double caudal; // Caudal (kg/h)

	@Temporal(TemporalType.TIMESTAMP)
	@Column(nullable = false)
	private Date estampaTiempo; // Momento de recepción del dato
}