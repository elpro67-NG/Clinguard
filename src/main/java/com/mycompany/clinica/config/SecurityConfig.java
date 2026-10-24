
package com.clinguard.clinguard.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;

import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.session.HttpSessionEventPublisher;

@Configuration
@EnableMethodSecurity
public class SecurityConfig {

    // =====================================================
    // ENCRIPTACIÓN DE CONTRASEÑAS
    // =====================================================

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    // =====================================================
    // CONTROL DE SESIONES
    // =====================================================

    @Bean
    public HttpSessionEventPublisher httpSessionEventPublisher() {
        return new HttpSessionEventPublisher();
    }

    // =====================================================
    // CONFIGURACIÓN PRINCIPAL DE SEGURIDAD
    // =====================================================

    @Bean
    public SecurityFilterChain securityFilterChain(
            HttpSecurity http
    ) throws Exception {

        http

            // =================================================
            // AUTORIZACIÓN DE RUTAS
            // =================================================

            .authorizeHttpRequests(auth -> auth

                // =============================================
                // RUTAS PÚBLICAS
                // =============================================

                .requestMatchers(
                    "/",
                    "/login",
                    "/registro",
                    "/session-expired",
                    "/error",
                    "/error/**",
                    "/css/**",
                    "/js/**",
                    "/images/**",
                    "/img/**",
                    "/fonts/**",
                    "/favicon.ico"
                )
                .permitAll()

                // =============================================
                // DASHBOARD GENERAL
                // =============================================

                .requestMatchers("/dashboard")
                .hasAnyRole(
                    "ADMIN",
                    "MEDICO",
                    "ENFERMERO",
                    "RECEPCIONISTA",
                    "USUARIO"
                )

                // =============================================
                // PERFIL DE USUARIO
                // =============================================

                .requestMatchers(
                    "/perfil",
                    "/perfil/**"
                )
                .hasAnyRole(
                    "ADMIN",
                    "MEDICO",
                    "ENFERMERO",
                    "RECEPCIONISTA",
                    "USUARIO"
                )

                // =============================================
                // DASHBOARD RECEPCIONISTA
                // =============================================

                .requestMatchers(
                    "/recepcionista",
                    "/recepcionista/**"
                )
                .hasRole("RECEPCIONISTA")

                // =============================================
                // GESTIÓN ADMINISTRATIVA DE RECEPCIÓN
                // =============================================

                .requestMatchers(
                    "/recepcion",
                    "/recepcion/**"
                )
                .hasAnyRole(
                    "ADMIN",
                    "RECEPCIONISTA"
                )

                // =============================================
                // ADMINISTRADOR
                // =============================================

                .requestMatchers(
                    "/admin",
                    "/admin/**"
                )
                .hasRole("ADMIN")

                // =============================================
                // GESTIÓN DE USUARIOS
                // =============================================

                .requestMatchers(
                    "/usuarios",
                    "/usuarios/**"
                )
                .hasRole("ADMIN")

                // =============================================
                // GESTIÓN DE MÉDICOS
                // =============================================

                .requestMatchers(
                    "/medicos",
                    "/medicos/**"
                )
                .hasRole("ADMIN")

                // =============================================
                // GESTIÓN DE ENFERMEROS
                // =============================================

                .requestMatchers(
                    "/enfermeros",
                    "/enfermeros/**"
                )
                .hasRole("ADMIN")

                // =============================================
                // ANÁLISIS
                // =============================================

                .requestMatchers(
                    "/analisis",
                    "/analisis/**"
                )
                .hasAnyRole(
                    "ADMIN",
                    "MEDICO"
                )

                // =============================================
                // REPORTES CLÍNICOS
                // =============================================

                .requestMatchers(
                    "/reportes",
                    "/reportes/**"
                )
                .hasAnyRole(
                    "ADMIN",
                    "MEDICO"
                )

                // =============================================
                // CONVERSIONES MÉDICAS
                // =============================================

                .requestMatchers(
                    "/conversiones",
                    "/conversiones/**"
                )
                .hasAnyRole(
                    "ADMIN",
                    "MEDICO",
                    "ENFERMERO"
                )

                // =============================================
                // MEDICAMENTOS
                // =============================================

                .requestMatchers(
                    "/medicamentos",
                    "/medicamentos/**"
                )
                .hasAnyRole(
                    "ADMIN",
                    "MEDICO",
                    "ENFERMERO"
                )

                // =============================================
                // PACIENTES - ELIMINAR
                // =============================================

                .requestMatchers(
                    HttpMethod.POST,
                    "/pacientes/eliminar/**"
                )
                .hasRole("ADMIN")

                // =============================================
                // PACIENTES - CREAR / ACTUALIZAR
                // =============================================

                .requestMatchers(
                    HttpMethod.POST,
                    "/pacientes/guardar",
                    "/pacientes/actualizar/**"
                )
                .hasAnyRole(
                    "ADMIN",
                    "MEDICO"
                )

                // =============================================
                // PACIENTES - CONSULTAR
                // =============================================

                .requestMatchers(
                    HttpMethod.GET,
                    "/pacientes",
                    "/pacientes/**"
                )
                .hasAnyRole(
                    "ADMIN",
                    "MEDICO",
                    "ENFERMERO"
                )

                // =============================================
                // PACIENTES - OTRAS OPERACIONES
                // =============================================

                .requestMatchers(
                    "/pacientes",
                    "/pacientes/**"
                )
                .denyAll()

                // =============================================
                // CITAS - ELIMINAR
                // =============================================

                .requestMatchers(
                    HttpMethod.POST,
                    "/citas/eliminar/**"
                )
                .hasRole("ADMIN")

                // =============================================
                // CITAS - CREAR / ACTUALIZAR
                // =============================================

                .requestMatchers(
                    HttpMethod.POST,
                    "/citas/guardar",
                    "/citas/actualizar/**",
                    "/citas/estado/**"
                )
                .hasAnyRole(
                    "ADMIN",
                    "MEDICO",
                    "ENFERMERO"
                )

                // =============================================
                // CITAS - CONSULTAR
                // =============================================

                .requestMatchers(
                    HttpMethod.GET,
                    "/citas",
                    "/citas/**"
                )
                .hasAnyRole(
                    "ADMIN",
                    "MEDICO",
                    "ENFERMERO",
                    "USUARIO"
                )

                // =============================================
                // CITAS - OTRAS OPERACIONES
                // =============================================

                .requestMatchers(
                    "/citas",
                    "/citas/**"
                )
                .denyAll()

                // =============================================
                // HISTORIAL - ELIMINAR
                // =============================================

                .requestMatchers(
                    HttpMethod.POST,
                    "/historial/eliminar/**"
                )
                .hasRole("ADMIN")

                // =============================================
                // HISTORIAL - CREAR / ACTUALIZAR
                // =============================================

                .requestMatchers(
                    HttpMethod.POST,
                    "/historial/guardar",
                    "/historial/actualizar/**"
                )
                .hasAnyRole(
                    "ADMIN",
                    "MEDICO"
                )

                // =============================================
                // HISTORIAL - FORMULARIOS DE CREACIÓN Y EDICIÓN
                // =============================================

                .requestMatchers(
                    HttpMethod.GET,
                    "/historial/nuevo",
                    "/historial/editar/**"
                )
                .hasAnyRole(
                    "ADMIN",
                    "MEDICO"
                )

                // =============================================
                // HISTORIAL - CONSULTAR
                // =============================================

                .requestMatchers(
                    HttpMethod.GET,
                    "/historial",
                    "/historial/ver/**",
                    "/historial/paciente/**"
                )
                .hasAnyRole(
                    "ADMIN",
                    "MEDICO",
                    "ENFERMERO",
                    "USUARIO"
                )

                // =============================================
                // HISTORIAL - OTRAS OPERACIONES
                // =============================================

                .requestMatchers(
                    "/historial",
                    "/historial/**"
                )
                .denyAll()

                // =============================================
                // RESTO DE RUTAS
                // =============================================

                .anyRequest()
                .authenticated()

            )

            // =================================================
            // LOGIN
            // =================================================

            .formLogin(form -> form

                .loginPage("/login")

                .loginProcessingUrl("/login")

                .defaultSuccessUrl(
                    "/dashboard",
                    true
                )

                .failureUrl(
                    "/login?error=true"
                )

                .permitAll()

            )

            // =================================================
            // LOGOUT
            // =================================================

            .logout(logout -> logout

                .logoutUrl("/logout")

                .logoutSuccessUrl(
                    "/login?logout=true"
                )

                .invalidateHttpSession(true)

                .clearAuthentication(true)

                .deleteCookies("JSESSIONID")

                .permitAll()

            )

            // =================================================
            // CONTROL DE SESIONES
            // =================================================

            .sessionManagement(session -> session

                // Evita reutilizar el mismo identificador
                // de sesión después de iniciar sesión.

                .sessionFixation(
                    fixation -> fixation.migrateSession()
                )

                // Evita mostrar el mensaje de expiración
                // automáticamente ante sesiones inválidas.

                .invalidSessionUrl("/login")

                // Una sola sesión activa por usuario.

                .maximumSessions(1)

                // Permite un nuevo inicio de sesión;
                // la sesión anterior deja de ser válida.

                .maxSessionsPreventsLogin(false)

            )

            // =================================================
            // ACCESO DENEGADO
            // =================================================

            .exceptionHandling(exception -> exception

                .accessDeniedPage("/error/403")

            );

        return http.build();
    }
}
