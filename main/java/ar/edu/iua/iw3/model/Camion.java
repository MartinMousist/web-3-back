package ar.edu.iua.iw3.model;

import java.io.Serializable; 

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table; 
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter; 

@Entity
@Table(name = "camiones")
@AllArgsConstructor
@NoArgsConstructor
@Getter
@Setter
public class Camion implements Serializable {

	private static final long serialVersionUID = 1L;

	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	private Long id;

	@Column(length = 50, unique = true, nullable = false)
	private String codExterno; 
	
	@Column(length = 20, unique = true, nullable = false)
	private String patente;
	
	@Column(length = 255)
	private String descripcion;
	
	@Column(length = 100)
	private String cisternado;
}