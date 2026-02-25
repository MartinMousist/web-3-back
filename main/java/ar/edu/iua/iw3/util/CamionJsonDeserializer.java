package ar.edu.iua.iw3.util;

import java.io.IOException;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.deser.std.StdDeserializer;

import ar.edu.iua.iw3.model.Camion;

public class CamionJsonDeserializer extends StdDeserializer<Camion> {

    private static final long serialVersionUID = 1L;

    public CamionJsonDeserializer() {
        this(null);
    }

    public CamionJsonDeserializer(Class<?> vc) {
        super(vc);
    }

    @Override
    public Camion deserialize(JsonParser jp, DeserializationContext ctxt) throws IOException {
        JsonNode node = jp.getCodec().readTree(jp);

        Long id = node.get("id") != null && node.get("id").canConvertToLong() ? node.get("id").asLong() : null;
        if (id != null && id > 0) {
            Camion c = new Camion();
            c.setId(id);
            return c;
        }
        
        String patente = JsonUtiles.getString(node, new String[]{"patente", "PATENTE"}, null);
        
        String codExterno = JsonUtiles.getString(node, new String[]{"codExterno", "cod_externo", "code"}, patente);
        
        if (patente != null || codExterno != null) {
             Camion c = new Camion();
             c.setPatente(patente);
             c.setCodExterno(codExterno);
             
             c.setDescripcion(JsonUtiles.getString(node, new String[]{"descripcion", "desc"}, null));
             c.setCisternado(JsonUtiles.getString(node, new String[]{"cisternado", "tipo"}, null));
             
             return c;
        }

        return null; 
    }
}