package jwtSecurity.example.jwtDemo.Service.Impl;

import jwtSecurity.example.jwtDemo.Config.JwtTokenProvider;
import jwtSecurity.example.jwtDemo.Dto.LoginDto;
import jwtSecurity.example.jwtDemo.Service.AuthService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

import org.springframework.stereotype.Service;

import lombok.extern.slf4j.Slf4j;

@Slf4j
@Service
public class AuthServiceImpl implements AuthService {

    @Autowired
    private AuthenticationManager authenticationManager;
    @Autowired
    private JwtTokenProvider jwtTokenProvider;

    //@Autowired
    //PasswordEncoder    passwordEncoder;

    @Override
    public String login(LoginDto loginDto) {
        log.info("loginDto:{}", loginDto);
        /*
        @Bean
        public static PasswordEncoder passwordEncoder(){
            return new BCryptPasswordEncoder();
        } */
        ///String epw = passwordEncoder.encode(loginDto.getPassword());
        ///log.info("epw:{}", epw);

        // 01 - AuthenticationManager is used to authenticate the user
        Authentication authentication = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(
                loginDto.getUsername(),
                loginDto.getPassword()
        ));

        /* 02 - SecurityContextHolder is used to allows the rest of the application to know
        that the user is authenticated and can use user data from Authentication object */
        SecurityContextHolder.getContext().setAuthentication(authentication);

        // 03 - Generate the token based on username and secret key
        String token = jwtTokenProvider.generateToken(authentication);

        log.info("login token:{}", token);

        // 04 - Return the token to controller
        return token;
    }
}