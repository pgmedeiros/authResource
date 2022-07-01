package com.springsecurityteste.basico.security;

import com.springsecurityteste.basico.user.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class JpaUserDetailsService implements UserDetailsService {

    @Autowired
    private UserRepository repository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        var possivelUsuario = repository.findByUsername(username);

        if (possivelUsuario.isEmpty()) {
            throw new UsernameNotFoundException("Usuário não foi encontrado amigo.");
        }

        final var simpleGrantedAuthority = new SimpleGrantedAuthority("ROLE_" + possivelUsuario.get().getTipo());

        return new User(possivelUsuario.get().getUsername(),
                possivelUsuario.get().getPassword(),
                List.of(simpleGrantedAuthority));
    }
}
