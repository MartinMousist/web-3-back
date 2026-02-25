package ar.edu.iua.iw3;

import java.util.HashSet;
import java.util.Set;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import ar.edu.iua.iw3.auth.IUserBusiness;
import ar.edu.iua.iw3.auth.Role;
import ar.edu.iua.iw3.auth.RoleRepository;
import ar.edu.iua.iw3.auth.User;
import ar.edu.iua.iw3.auth.UserRepository;

@Component
public class DataLoader implements CommandLineRunner {

    @Autowired
    private RoleRepository roleRepository;
    @Autowired
    private UserRepository userRepository;
    @Autowired
    private IUserBusiness userBusiness;
    @Autowired
    private PasswordEncoder passwordEncoder;

    @Override
    public void run(String... args) throws Exception {
        // 1. Crear Roles si no existen
        createRole("ROLE_ADMIN", "Administrador");
        createRole("ROLE_SAP", "Sistema SAP");
        createRole("ROLE_TMS", "Sistema Balanza");
        createRole("ROLE_CLI", "Cliente/Chofer");
        createRole("ROLE_USER", "Operador");

        // 2. Crear Admin con TODOS los roles si no existe
        if (userRepository.findOneByUsernameOrEmail("admin", "admin").isEmpty()) {
            User admin = new User();
            admin.setUsername("admin");
            admin.setEmail("admin@test.com");
            admin.setPassword("123"); 
            
            Set<Role> roles = new HashSet<>();
            // Asignamos todos los roles para poder usar el simulador sin errores 403
            roleRepository.findByName("ROLE_ADMIN").ifPresent(roles::add);
            roleRepository.findByName("ROLE_SAP").ifPresent(roles::add);
            roleRepository.findByName("ROLE_TMS").ifPresent(roles::add);
            roleRepository.findByName("ROLE_CLI").ifPresent(roles::add);
            roleRepository.findByName("ROLE_USER").ifPresent(roles::add);

            admin.setRoles(roles);

            // El método save ya se encarga de la encriptación y estados por defecto
            userBusiness.save(admin, passwordEncoder);
            System.out.println("✅ --- SUPER USUARIO 'admin' CREADO CON TODOS LOS ROLES (Pass: 123) ---");
        }
    }

    private void createRole(String name, String desc) {
        // Se requiere que RoleRepository tenga definido el método findByName
        if (roleRepository.findByName(name).isEmpty()) {
            Role r = new Role();
            r.setName(name);
            r.setDescription(desc);
            roleRepository.save(r);
        }
    }
}