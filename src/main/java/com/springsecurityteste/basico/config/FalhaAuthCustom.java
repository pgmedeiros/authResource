package com.springsecurityteste.basico.config;

import com.springsecurityteste.basico.user.enums.EStatus;
import com.springsecurityteste.basico.user.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.stereotype.Component;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Component
public class FalhaAuthCustom implements AuthenticationFailureHandler {

    @Autowired
    private CustomService customService;

    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {
        var cache = CacheLogin.getCacheLogin();
        String username = request.getParameter("username");
        if (customService.verificaExistenciaBanco(username)) {
            customService.verificaBloqueioUsuario(cache, username);
            cache.adicionar(username);
            System.out.println(cache.pegarNumeroDeTentativas(username));
        }
        throw new RuntimeException("Não foi possível realizar o login");
    }


}
