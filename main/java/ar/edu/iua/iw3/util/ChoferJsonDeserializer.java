package ar.edu.iua.iw3.util;

import java.io.IOException;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.deser.std.StdDeserializer;

import ar.edu.iua.iw3.model.Chofer;

public class ChoferJsonDeserializer extends StdDeserializer<Chofer> {

    private static final long serialVersionUID = 1L;

    public ChoferJsonDeserializer() {
        this(null);
    }

    public ChoferJsonDeserializer(Class<?> vc) {
        super(vc);
    }

    @Override
    public Chofer deserialize(JsonParser jp, DeserializationContext ctxt) throws IOException {
        JsonNode node = jp.getCodec().readTree(jp);

        Long id = node.get("id") != null && node.get("id").canConvertToLong() ? node.get("id").asLong() : null;
        if (id != null && id > 0) {
            Chofer c = new Chofer();
            c.setId(id);
            return c;
        }

        String documento = JsonUtiles.getString(node, new String[]{"documento", "doc", "dni"}, null);
        String codExterno = JsonUtiles.getString(node, new String[]{"codExterno", "cod_externo", "code"}, null);

        if (documento != null || codExterno != null) {
            Chofer c = new Chofer();
            if (documento != null) {
                c.setDocumento(documento);
            }
            if (codExterno != null) {
                c.setCodExterno(codExterno);
            } else if (documento != null) {
                 c.setCodExterno(documento);
            }
            
            c.setNombre(JsonUtiles.getString(node, new String[]{"nombre", "name"}, null));
            c.setApellido(JsonUtiles.getString(node, new String[]{"apellido", "lastname"}, null));

            return c;
        }

        return null; 
    }
}