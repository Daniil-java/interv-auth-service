package com.kuklin.authentication.dtos;

import lombok.Data;
import lombok.experimental.Accessors;

import java.math.BigDecimal;
import java.util.Set;

@Data
@Accessors(chain = true)
public class UserDto {
    private Long id;
    private String name;
    private String password;
    private Set<String> roles;
    private String jobTitle;
    private BigDecimal balance;
    private String properties;

}
