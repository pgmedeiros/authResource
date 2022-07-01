package com.springsecurityteste.basico.config;

import lombok.Data;

import java.util.HashMap;
import java.util.Map;

@Data
public class CacheLogin {

    private static Map<String, Integer> tentativa = new HashMap<>();
    private static CacheLogin cacheLogin;

    private CacheLogin() {}

    public static CacheLogin getCacheLogin() {
        if (cacheLogin == null) {
            cacheLogin = new CacheLogin();
        }
        return cacheLogin;
    }

    public void adicionar(String username) {
        if (!existe(username)) {
            tentativa.put(username, 1);
        } else {
            var atualNumeroDeTentativas = tentativa.get(username);
            var numeroDeTentativasAtualizado = atualNumeroDeTentativas + 1;
            tentativa.put(username, numeroDeTentativasAtualizado);
        }
    }

    public Integer pegarNumeroDeTentativas(String username) {
        return tentativa.get(username);
    }

    public void remover(String username) {
        tentativa.remove(username);
    }

    public boolean existe(String username) {
        return tentativa.containsKey(username);
    }
 }
