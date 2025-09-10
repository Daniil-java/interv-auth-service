package com.kuklin.authentication.services;

import com.kuklin.authentication.dtos.Role;
import com.kuklin.authentication.dtos.UserDto;
import com.kuklin.authentication.integrations.UserServiceFeignClient;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Set;

@Service
@RequiredArgsConstructor
public class RegistrationService {
    private final PasswordEncoder passwordEncoder;
    private final UserServiceFeignClient userClient;

    public void register(String username, String rawPassword) {
        UserDto dto = new UserDto()
                .setName(username)
                .setPassword(passwordEncoder.encode(rawPassword))
                .setRoles(Set.of(Role.USER.getRoleName()));

        userClient.createUser(dto);
    }
}
