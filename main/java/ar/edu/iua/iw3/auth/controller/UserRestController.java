package ar.edu.iua.iw3.auth.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import ar.edu.iua.iw3.auth.IUserBusiness;
import ar.edu.iua.iw3.auth.User;
import ar.edu.iua.iw3.controllers.BaseRestController;
import ar.edu.iua.iw3.controllers.Constants;
import ar.edu.iua.iw3.util.IStandartResponseBusiness;

@RestController
@RequestMapping(Constants.URL_BASE + "/users")
public class UserRestController extends BaseRestController {

    @Autowired
    private IUserBusiness userBusiness;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private IStandartResponseBusiness response;

    // Listar todos (Solo Admin)
    @GetMapping("")
    @PreAuthorize("hasRole('ROLE_ADMIN')")
    public ResponseEntity<?> list() {
        try {
            return new ResponseEntity<>(userBusiness.list(), HttpStatus.OK);
        } catch (Exception e) {
            return new ResponseEntity<>(response.build(HttpStatus.INTERNAL_SERVER_ERROR, e, e.getMessage()), HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    // Editar Usuario (Roles, Password, etc)
    @PutMapping("/update")
    @PreAuthorize("hasRole('ROLE_ADMIN')")
    public ResponseEntity<?> updateUser(@RequestBody User user) {
        try {
            // Buscamos el usuario original para no perder datos si vienen nulos
            User original = userBusiness.load(user.getUsername());
            
            // Si viene password, la encriptamos, sino mantenemos la anterior
            if(user.getPassword() != null && !user.getPassword().isEmpty()) {
                original.setPassword(user.getPassword());
            }
            
            // Actualizamos roles si vienen
            if(user.getRoles() != null && !user.getRoles().isEmpty()) {
                original.setRoles(user.getRoles());
            }
            
            original.setEnabled(user.isEnabled());
            
            // Guardamos (UserBusiness ya se encarga de encriptar si usas save)
            userBusiness.save(original, passwordEncoder);
            return new ResponseEntity<>(HttpStatus.OK);
        } catch (Exception e) {
            return new ResponseEntity<>(response.build(HttpStatus.INTERNAL_SERVER_ERROR, e, e.getMessage()), HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }
}