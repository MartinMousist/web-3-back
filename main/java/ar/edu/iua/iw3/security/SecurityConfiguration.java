package ar.edu.iua.iw3.security;

import java.util.Arrays;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import ar.edu.iua.iw3.auth.IUserBusiness;
import ar.edu.iua.iw3.auth.custom.CustomAuthenticationManager;
import ar.edu.iua.iw3.auth.filters.JWTAuthorizationFilter;

@Configuration
@EnableWebSecurity
public class SecurityConfiguration {

    @Autowired
    private IUserBusiness userBusiness;

    @Bean
    public PasswordEncoder bCryptPasswordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public AuthenticationManager authenticationManager() {
        return new CustomAuthenticationManager(bCryptPasswordEncoder(), userBusiness);
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        AuthenticationManager authManager = authenticationManager();

        http.cors(cors -> cors.configurationSource(corsConfigurationSource()))
            .csrf(csrf -> csrf.disable())
            .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS));

        http.authorizeHttpRequests(auth -> auth
                .requestMatchers(HttpMethod.POST, "/api/v1/login").permitAll()
                .requestMatchers(HttpMethod.POST, "/api/v1/register").permitAll()

                // 1. Crear orden -> Solo SAP
                .requestMatchers(HttpMethod.POST, "/api/v1/ordenes").hasRole("SAP")
                
                // 2. Registro de tara -> Solo TMS
                .requestMatchers(HttpMethod.PUT, "/api/v1/ordenes/*/tara").hasRole("TMS")
                
                // 3. Recepción de datos -> Solo CLI
                .requestMatchers(HttpMethod.POST, "/api/v1/ordenes/flow").hasRole("CLI")
                
                // 4. Cierre de orden -> Solo CLI
                .requestMatchers(HttpMethod.PUT, "/api/v1/ordenes/*/close").hasRole("CLI")
                
                // 5. Pesaje final -> Solo TMS
                .requestMatchers(HttpMethod.PUT, "/api/v1/ordenes/*/final-weighing").hasRole("TMS")
                
                // 6. Conciliación y Alarmas -> Solo ADMIN
                .requestMatchers(HttpMethod.GET, "/api/v1/ordenes/*/conciliacion").hasRole("ADMIN")
                
                // ADAPTACIÓN: Soporte para PUT y PATCH en alarmas para asegurar compatibilidad con el frontend
                .requestMatchers(HttpMethod.PUT, "/api/v1/ordenes/*/aceptar-alarma").hasRole("ADMIN")
                .requestMatchers(HttpMethod.PATCH, "/api/v1/ordenes/*/aceptar-alarma").hasRole("ADMIN")

                .requestMatchers("/error").permitAll()
                .requestMatchers("/api/v1/**").authenticated()
                .anyRequest().authenticated());

        http.addFilter(new JWTAuthorizationFilter(authManager));

        return http.build();
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        // ADAPTACIÓN: Agregamos soporte para ambos puertos comunes de Vue y permitimos PATCH
        configuration.setAllowedOrigins(Arrays.asList("http://localhost:5173", "http://localhost:5174")); 
        configuration.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"));
        configuration.setAllowedHeaders(Arrays.asList("Authorization", "Content-Type", "x-auth-token"));
        configuration.setAllowCredentials(true);
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }
}