package com.luv2code.springboot.cruddemo.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class SecurityConfig {

    private static final String EMPLOYEE = "EMPLOYEE";
    private static final String MANAGER = "MANAGER";
    private static final String ADMIN = "ADMIN";
    private static final String BASE_URL = "/api/employees";


    @Bean
    public InMemoryUserDetailsManager userDetailsManager() {
        UserDetails john = User.builder()
                .username("john")
                .password("{noop}john")
                .roles(EMPLOYEE)
                .build();

        UserDetails mary = User.builder()
                .username("mary")
                .password("{noop}mary")
                .roles(EMPLOYEE, MANAGER)
                .build();

        UserDetails susan = User.builder()
                .username("susan")
                .password("{noop}susan")
                .roles(EMPLOYEE, MANAGER, ADMIN)
                .build();

        return new InMemoryUserDetailsManager(john, mary, susan);
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        return
                http
                        .csrf(AbstractHttpConfigurer::disable)
                        .authorizeHttpRequests(
                                auth ->
                                        auth
                                                .requestMatchers(HttpMethod.GET, BASE_URL).hasRole(EMPLOYEE)
                                                .requestMatchers(HttpMethod.GET, BASE_URL + "/**").hasRole(EMPLOYEE)
                                                .requestMatchers(HttpMethod.POST, BASE_URL).hasRole(MANAGER)
                                                .requestMatchers(HttpMethod.PUT, BASE_URL).hasRole(MANAGER)
                                                .requestMatchers(HttpMethod.DELETE, BASE_URL + "/**").hasRole(ADMIN)
                        )
                        .httpBasic()
                        .and()
                        .build();
    }
}
