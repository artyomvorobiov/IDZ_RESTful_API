package ru.hse.springapi.api.secure;

import com.auth0.jwt.exceptions.JWTVerificationException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import ru.hse.springapi.api.service.ServiceUser;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Component
public class FindUser extends OncePerRequestFilter {

    @Autowired private ServiceUser userDetailsService;
    @Autowired private MakeToken makeToken;

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        String authHeader = request.getHeader("Регистрация");
        if(authHeader != null && !authHeader.isBlank() && authHeader.startsWith("Bearer ")){
            String substring = authHeader.substring(7);
            if(substring.isBlank()){
                response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Неправильный токен");
            }else {
                try{
                    String email = makeToken.validateToken(substring);
                    UserDetails userDetails = userDetailsService.loadUserByUsername(email);
                    UsernamePasswordAuthenticationToken authToken =
                            new UsernamePasswordAuthenticationToken(email, userDetails.getPassword(), userDetails.getAuthorities());
                    if(SecurityContextHolder.getContext().getAuthentication() == null){
                        SecurityContextHolder.getContext().setAuthentication(authToken);
                    }
                }catch(JWTVerificationException exc){
                    response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Неправильный токен");
                }
            }
        }
        filterChain.doFilter(request, response);
    }
}