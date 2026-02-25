package ar.edu.iua.iw3.auth.controller;

import java.util.ArrayList;
import java.util.Date;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;

import ar.edu.iua.iw3.auth.IUserBusiness;
import ar.edu.iua.iw3.auth.User;
import ar.edu.iua.iw3.auth.custom.CustomAuthenticationManager;
import ar.edu.iua.iw3.auth.filters.AuthConstants;
import ar.edu.iua.iw3.controllers.BaseRestController;
import ar.edu.iua.iw3.controllers.Constants;
import ar.edu.iua.iw3.model.business.BusinessException;
import ar.edu.iua.iw3.util.IStandartResponseBusiness;

@RestController
@RequestMapping(Constants.URL_BASE) // Esto mapea a /api/v1
public class AuthRestController extends BaseRestController {

    @Autowired
    private AuthenticationManager authManager;

    @Autowired
    private IUserBusiness userBusiness;

    @Autowired
    private PasswordEncoder pEncoder;

    @Autowired
    private IStandartResponseBusiness response;

    public static class LoginRequest {
    public String username;
    public String password;
}
    public static class LoginDTO {
        public String username;
        public String password;
    }
    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody LoginDTO data) { // CAMBIADO A @RequestBody
        try {
            Authentication auth = authManager.authenticate(
                ((CustomAuthenticationManager) authManager).authWrap(data.username, data.password));
            
            User user = (User) auth.getPrincipal();
            
            // Generación del token...
            String token = JWT.create()
                .withSubject(user.getUsername())
                .withClaim("roles", new ArrayList<>(user.getAuthoritiesStr()))
                .withExpiresAt(new Date(System.currentTimeMillis() + AuthConstants.EXPIRATION_TIME))
                .sign(Algorithm.HMAC512(AuthConstants.SECRET.getBytes()));

            // Devuelve el token en un formato que el frontend pueda leer fácilmente
            // Es mejor devolver un objeto JSON { "token": "..." }
            return new ResponseEntity<>(java.util.Map.of("token", token), HttpStatus.OK);
        } catch (Exception e) {
            return new ResponseEntity<>(e.getMessage(), HttpStatus.UNAUTHORIZED);
        }
    }


    // --- ENDPOINT DE REGISTRO ---
	@PostMapping(value = "/register", produces = MediaType.APPLICATION_JSON_VALUE)
	public ResponseEntity<?> register(@RequestBody User user) {
		try {
			// Llama al método save que acabamos de actualizar
			User newUser = userBusiness.save(user, pEncoder);
			return new ResponseEntity<>(newUser, HttpStatus.CREATED);
		} catch (BusinessException e) {
			return new ResponseEntity<>(response.build(HttpStatus.INTERNAL_SERVER_ERROR, e, e.getMessage()),
					HttpStatus.INTERNAL_SERVER_ERROR);
		}
	}
}