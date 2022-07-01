package com.springsecurityteste.basico.user.model;

import com.springsecurityteste.basico.user.enums.EStatus;
import com.springsecurityteste.basico.user.enums.ETipo;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import javax.persistence.*;

@Entity
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class Users {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Integer id;
    @Column(unique = true, nullable = false)
    private String username;
    @Column(nullable = false)
    private String password;
    @Enumerated(EnumType.STRING)
    private ETipo tipo;
    @Enumerated(EnumType.STRING)
    private EStatus status;

}
