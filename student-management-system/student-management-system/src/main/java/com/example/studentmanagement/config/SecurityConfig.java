package com.example.studentmanagement.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
public class SecurityConfig {

    // Password Encoder Bean (using BCryptPasswordEncoder)
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    // In-Memory UserDetailsManager Bean for authentication (Good for testing/dev purposes)
    @Bean
    public InMemoryUserDetailsManager userDetailsService() {
        UserDetails user = User.builder()
                .username("user")
                .password(passwordEncoder().encode("password"))  // Encode password
                .roles("USER")
                .build();

        UserDetails admin = User.builder()
                .username("admin")
                .password(passwordEncoder().encode("adminpass"))
                .roles("ADMIN")
                .build();

        return new InMemoryUserDetailsManager(user, admin);  // Add both users
    }

    // SecurityFilterChain for configuring HTTP Basic Authentication (Spring Security 6.1+)
    @Bean
    public HttpSecurity securityFilterChain(HttpSecurity http) throws Exception {
        http
                .authorizeRequests()
                .requestMatchers("/api/students/**").authenticated()  // Secure student API
                .requestMatchers("/api/admin/**").hasRole("ADMIN")  // Only allow admin for admin endpoints
                .and()
                .httpBasic(Customizer.withDefaults());  // Replacing deprecated `httpBasic()` method

        // CSRF Configuration (No longer deprecated)
        http.csrf(csrf -> csrf.disable());  // Disable CSRF (appropriate for stateless APIs)

        return http;
    }
}
