package ru.hse.springapi.api.secure;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import ru.hse.springapi.api.service.ServiceUser;

import javax.servlet.http.HttpServletResponse;

@Configuration
@EnableWebSecurity
public class MainSecurity extends WebSecurityConfigurerAdapter {

    @Autowired private FindUser filter;
    @Autowired private ServiceUser uds;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.csrf().disable();
        http.authorizeHttpRequests(requests -> {
                    try {
                        requests
                                .antMatchers("/auth/**").permitAll()
                                .antMatchers("/api/user/**").hasRole("USER")
                                .and()
                                .userDetailsService(uds)
                                .exceptionHandling()
                                .authenticationEntryPoint(
                                        (request, response, authException) ->
                                                response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Unauthorized"))
                                .and()
                                .sessionManagement()
                                .sessionCreationPolicy(SessionCreationPolicy.STATELESS);
                    } catch (Exception e) {
                        throw new RuntimeException(e);
                    }

                    http.addFilterBefore( filter, UsernamePasswordAuthenticationFilter.class);
                }
        );
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }
}