package com.springsecurityteste.basico.user.service;

import com.springsecurityteste.basico.user.dto.UsuarioDto;
import com.springsecurityteste.basico.user.model.Users;
import com.springsecurityteste.basico.user.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
public class UsuarioService {

    @Autowired
    private UserRepository repository;
    @Autowired
    private PasswordEncoder passwordEncoder;

    public Users criarUsuario(UsuarioDto usuarioDto) {
        usuarioDto.setPassword(passwordEncoder.encode(usuarioDto.getPassword()));
        return repository.save(of(usuarioDto));
    }

    Users of(UsuarioDto usuarioDto) {
        return Users
                .builder()
                .username(usuarioDto.getUsername())
                .password(usuarioDto.getPassword())
                .build();
    }

}
