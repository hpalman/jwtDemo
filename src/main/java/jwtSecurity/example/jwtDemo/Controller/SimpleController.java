package jwtSecurity.example.jwtDemo.Controller;

import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import lombok.extern.slf4j.Slf4j;

@Slf4j
@RestController
@RequestMapping("/api/")
public class SimpleController {

    // ADMIN 롤을 가진 사용자여야 함
    @PreAuthorize("hasRole('ADMIN')")
    @GetMapping("/admin")
    public ResponseEntity<String> helloAdmin(){
        log.info("I");
        ResponseEntity<String> responseEntity = ResponseEntity.ok("Hello Admin");
        log.info("O");
        return responseEntity;
    }

    // USER 롤을 가진 사용자여야 함
    @PreAuthorize("hasRole('USER')")
    @GetMapping("/user")
    public ResponseEntity<String> helloUser(){
        log.info("I");
        ResponseEntity<String> responseEntity = ResponseEntity.ok("Hello User");
        log.info("O");
        return responseEntity;
    }
}