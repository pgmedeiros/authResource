package com.springsecurityteste.basico.user.controller;

import com.springsecurityteste.basico.user.dto.UserResponse;
import com.springsecurityteste.basico.user.dto.UsuarioDto;
import com.springsecurityteste.basico.user.model.Users;
import com.springsecurityteste.basico.user.service.UsuarioService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("api/usuario")
public class UsuarioController {

    @Autowired
    private UsuarioService service;

    @PostMapping
    public Users criarUsuario(UsuarioDto usuarioDto) {
        return service.criarUsuario(usuarioDto);
    }

    @GetMapping("{id}")
    public UserResponse retornar() {
       return UserResponse
                .builder()
                .id(1)
                .email("123123")
                .name("josé do egito")
                .build();
    }

}
