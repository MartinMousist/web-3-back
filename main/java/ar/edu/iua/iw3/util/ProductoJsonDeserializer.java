package ar.edu.iua.iw3.util;

import java.io.IOException;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.deser.std.StdDeserializer;

import ar.edu.iua.iw3.model.Producto;

public class ProductoJsonDeserializer extends StdDeserializer<Producto> {

    private static final long serialVersionUID = 1L;

    public ProductoJsonDeserializer() {
        this(null);
    }

    public ProductoJsonDeserializer(Class<?> vc) {
        super(vc);
    }

    @Override
    public Producto deserialize(JsonParser jp, DeserializationContext ctxt) throws IOException {
        JsonNode node = jp.getCodec().readTree(jp);

        Long id = node.get("id") != null && node.get("id").canConvertToLong() ? node.get("id").asLong() : null;
        if (id != null && id > 0) {
            Producto p = new Producto();
            p.setId(id);
            return p;
        }

        String nombre = JsonUtiles.getString(node, new String[]{"nombre", "name", "descripcion_corta"}, null);
        String codExterno = JsonUtiles.getString(node, new String[]{"codExterno", "cod_externo", "code"}, null);

        if (nombre != null || codExterno != null) {
            Producto p = new Producto();
            if (nombre != null) {
                p.setNombre(nombre);
            }
            if (codExterno != null) {
                p.setCodExterno(codExterno);
            } else if (nombre != null) {
                 // Si solo hay nombre, lo usamos como codExterno temporal
                 p.setCodExterno(nombre);
            }
            
            p.setDescripcion(JsonUtiles.getString(node, new String[]{"descripcion", "desc_larga"}, null));

            return p;
        }

        return null;
    }
}