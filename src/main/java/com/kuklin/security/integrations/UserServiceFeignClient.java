package com.kuklin.security.integrations;

import com.kuklin.security.configurations.FeignClientConfig;
import com.kuklin.sharedlibrary.UserDto;
import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.web.bind.annotation.*;

import java.util.Optional;

@FeignClient(
        value = "user-service-feign-client",
        url = "${integrations.user-service.url}",
        configuration = FeignClientConfig.class
)
public interface UserServiceFeignClient {

    @GetMapping("/api/v1/users/{userId}")
    Optional<UserDto> getUserById(@PathVariable Long userId);

    @PostMapping("/api/v1/users/")
    UserDto createUser(@RequestBody UserDto userDto);
    @GetMapping("/api/v1/users/")
    UserDto findByName(@RequestParam String userName);
}
