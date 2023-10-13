package com.luv2code.springboot.cruddemo.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.provisioning.UserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

import javax.sql.DataSource;

@Configuration
public class SecurityConfig {

    private static final String EMPLOYEE = "EMPLOYEE";
    private static final String MANAGER = "MANAGER";
    private static final String ADMIN = "ADMIN";
    private static final String BASE_URL = "/api/employees";


    @Bean
    public UserDetailsManager userDetailsManager(DataSource dataSource) {
        JdbcUserDetailsManager jdbcUserDetailsManager =  new JdbcUserDetailsManager(dataSource);
        jdbcUserDetailsManager.setUsersByUsernameQuery("SELECT user_id, pw, active FROM members WHERE user_id=?");
        jdbcUserDetailsManager.setAuthoritiesByUsernameQuery("SELECT user_id, role FROM roles WHERE user_id=?");
        return jdbcUserDetailsManager;
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
