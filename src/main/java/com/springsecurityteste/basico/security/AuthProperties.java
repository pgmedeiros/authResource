package com.springsecurityteste.basico.security;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;
import org.springframework.validation.annotation.Validated;

import javax.validation.constraints.NotBlank;
import javax.validation.constraints.NotNull;

@Component
@Validated
@Data
@ConfigurationProperties("cine.auth")
public class AuthProperties {
    @NotNull
    private JksProperties jks;

    @Data
    static class JksProperties {
        @NotBlank
        private String keypass;
        @NotBlank
        private String storepass;
        @NotBlank
        private String alias;
        @NotBlank
        private String path;
    }

}
