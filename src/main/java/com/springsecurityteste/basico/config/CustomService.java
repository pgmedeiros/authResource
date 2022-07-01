package com.springsecurityteste.basico.config;

import com.springsecurityteste.basico.user.enums.EStatus;
import com.springsecurityteste.basico.user.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class CustomService {

    @Autowired
    private UserRepository repository;

    public void verificaBloqueioUsuario(CacheLogin cache, String username) {
        if (cache.existe(username)) {
            var numeroTentativas = cache.pegarNumeroDeTentativas(username);
            if (numeroTentativas >= 3) {
                var user = repository.findByUsername(username).get();
                user.setStatus(EStatus.INATIVO);
                repository.save(user);
                throw new RuntimeException("Limite de tentativas excedido, usuário bloqueado");

            }
        }
    }

    public boolean verificaExistenciaBanco(String username) {
        return repository.findByUsername(username).isPresent();
    }

}
