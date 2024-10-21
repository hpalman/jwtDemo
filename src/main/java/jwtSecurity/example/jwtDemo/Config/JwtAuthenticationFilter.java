package jwtSecurity.example.jwtDemo.Config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    @Autowired
    private JwtTokenProvider jwtTokenProvider;

    private UserDetailsService userDetailsService;

    //Constructor
    public JwtAuthenticationFilter(JwtTokenProvider jwtTokenProvider, UserDetailsService userDetailsService) {
        log.info("I.0");
        this.jwtTokenProvider = jwtTokenProvider;
        this.userDetailsService = userDetailsService;
    }


    // This method is executed for every request intercepted by the filter.
    //And, it extract the token from the request header and validate the token.
    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
log.info("I.");
        // Get JWT token from HTTP request
        String token = getTokenFromRequest(request);
log.info("I. uri:{}, token:{}", request.getRequestURI(), token);

        // Validate Token
        if(StringUtils.hasText(token) && jwtTokenProvider.validateToken(token)){
            log.info("hasToken");
            // get username from token
            String username = jwtTokenProvider.getUsername(token);
            log.info("username:{}", username);

            UserDetails userDetails = userDetailsService.loadUserByUsername(username);
            log.info("userDetails:{}", userDetails);
            UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(
                    userDetails,
                    null,
                    userDetails.getAuthorities()
            );
            log.info("authenticationToken:{}", authenticationToken);

            authenticationToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

            log.info("setDetails");
            SecurityContextHolder.getContext().setAuthentication(authenticationToken);
            log.info("setAuthentication");
        }

        log.info("I.3");
        filterChain.doFilter(request, response);
        log.info("I.4");
    }

    // Extract the token
    private String getTokenFromRequest(HttpServletRequest request){
        log.info("I.0");
        String bearerToken = request.getHeader("Authorization");
        log.info("I.1. uri:{}, bearerToken:{}", request.getRequestURI(), bearerToken);

        if(StringUtils.hasText(bearerToken) && bearerToken.startsWith("Bearer ")){
            log.info("I.11");
            return bearerToken.substring(7, bearerToken.length());
        }
        log.info("I.3");

        return null;
    }
}