package ar.edu.iua.iw3.util;

import java.io.IOException;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.deser.std.StdDeserializer;

import ar.edu.iua.iw3.model.Cliente;

public class ClienteJsonDeserializer extends StdDeserializer<Cliente> {

    private static final long serialVersionUID = 1L;

    public ClienteJsonDeserializer() {
        this(null);
    }

    public ClienteJsonDeserializer(Class<?> vc) {
        super(vc);
    }

    @Override
    public Cliente deserialize(JsonParser jp, DeserializationContext ctxt) throws IOException {
        JsonNode node = jp.getCodec().readTree(jp);

        Long id = node.get("id") != null && node.get("id").canConvertToLong() ? node.get("id").asLong() : null;
        if (id != null && id > 0) {
            Cliente c = new Cliente();
            c.setId(id);
            return c;
        }

        String razonSocial = JsonUtiles.getString(node, new String[]{"razonSocial", "razon_social", "name"}, null);
        String codExterno = JsonUtiles.getString(node, new String[]{"codExterno", "cod_externo", "code"}, null);

        if (razonSocial != null || codExterno != null) {
            Cliente c = new Cliente();
            if (razonSocial != null) {
                c.setRazonSocial(razonSocial);
            }
            if (codExterno != null) {
                c.setCodExterno(codExterno);
            }
            
            c.setContacto(JsonUtiles.getString(node, new String[]{"contacto", "contact"}, null));

            return c;
        }

        return null;
    }
}