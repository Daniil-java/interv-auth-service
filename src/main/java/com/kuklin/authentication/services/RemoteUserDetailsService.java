package com.kuklin.authentication.services;

import com.kuklin.authentication.entities.RemoteUserDetails;
import com.kuklin.authentication.integrations.UserServiceFeignClient;
import com.kuklin.authentication.dtos.UserDto;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
@Slf4j
public class RemoteUserDetailsService implements UserDetailsService {
    private final UserServiceFeignClient userClient;
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        UserDto user = userClient.getUserByUsername(username);
        if (user == null) {
            log.error("User not found!");
            throw new UsernameNotFoundException("User not found: " + username);
        }
        return new RemoteUserDetails(user);

    }
}
