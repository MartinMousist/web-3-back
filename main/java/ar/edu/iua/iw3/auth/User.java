package ar.edu.iua.iw3.auth;

import java.util.Collection;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonProperty.Access;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.JoinTable;
import jakarta.persistence.ManyToMany;
import jakarta.persistence.Table;
import jakarta.persistence.Transient;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Entity
@Table(name = "users")
@AllArgsConstructor
@NoArgsConstructor
@Getter
@Setter
public class User implements UserDetails {

    private static final long serialVersionUID = 1L;

    @Column(columnDefinition = "tinyint default 1")
    private boolean accountNonExpired = true;

    @Column(columnDefinition = "tinyint default 1")
    private boolean accountNonLocked = true;

    @Column(columnDefinition = "tinyint default 1")
    private boolean credentialsNonExpired = true;

    @Column(columnDefinition = "tinyint default 1")
    private boolean enabled = true;

    public static final String VALIDATION_OK = "OK";
    public static final String VALIDATION_ACCOUNT_EXPIRED = "ACCOUNT_EXPIRED";
    public static final String VALIDATION_CREDENTIALS_EXPIRED = "CREDENTIALS_EXPIRED";
    public static final String VALIDATION_LOCKED = "LOCKED";
    public static final String VALIDATION_DISABLED = "DISABLED";

    public String validate() {
        if (!accountNonExpired)
            return VALIDATION_ACCOUNT_EXPIRED;
        if (!credentialsNonExpired)
            return VALIDATION_CREDENTIALS_EXPIRED;
        if (!accountNonLocked)
            return VALIDATION_LOCKED;
        if (!enabled)
            return VALIDATION_DISABLED;
        return VALIDATION_OK;
    }

    @Column(length = 255, nullable = false, unique = true)
    private String email;

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long idUser;

    @Column(length = 100, unique = true)
    private String username;

    @JsonProperty(access = Access.WRITE_ONLY)
    private String password;

    @ManyToMany(fetch = FetchType.EAGER)
    @JoinTable(name = "userroles", joinColumns = {
            @JoinColumn(name = "id_user", referencedColumnName = "idUser") }, inverseJoinColumns = {
                    @JoinColumn(name = "id_role", referencedColumnName = "id") })
    private Set<Role> roles;

    @Transient
    @JsonIgnore
    public boolean isInRole(Role role) {
        return isInRole(role.getName());
    }

    @Transient
    @JsonIgnore
    public boolean isInRole(String role) {
        for (Role r : getRoles())
            if (r.getName().equals(role))
                return true;
        return false;
    }

    @Transient
    @Override
    @JsonIgnore
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return getRoles().stream()
                .map(role -> new SimpleGrantedAuthority(role.getName()))
                .collect(Collectors.toList());
    }

    @Transient
    @JsonProperty("authorities")
    public List<String> getAuthoritiesStr() {
        return getRoles().stream().map(Role::getName).collect(Collectors.toList());
    }

    @Override
    @JsonIgnore
    public boolean isAccountNonExpired() {
        return accountNonExpired;
    }

    @Override
    @JsonIgnore
    public boolean isAccountNonLocked() {
        return accountNonLocked;
    }

    @Override
    @JsonIgnore
    public boolean isCredentialsNonExpired() {
        return credentialsNonExpired;
    }

    @Override
    @JsonIgnore
    public boolean isEnabled() {
        return enabled;
    }
}