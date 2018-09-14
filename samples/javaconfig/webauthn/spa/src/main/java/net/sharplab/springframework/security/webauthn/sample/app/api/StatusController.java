package net.sharplab.springframework.security.webauthn.sample.app.api;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RequestMapping("/api/status")
@RestController
public class StatusController {

    @RequestMapping("/200")
    public ResponseEntity status200(){
        return new ResponseEntity(HttpStatus.OK);
    }

    @RequestMapping("/401")
    public ResponseEntity status401(){
        return new ResponseEntity(HttpStatus.UNAUTHORIZED);
    }

    @RequestMapping("/403")
    public ResponseEntity status403(){
        return new ResponseEntity(HttpStatus.FORBIDDEN);
    }

}
