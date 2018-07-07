package net.sharplab.springframework.security.webauthn.sample.app.web;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;

/**
 * Controller for error handling
 */
@Controller
public class ErrorController {

    @RequestMapping("/error/500")
    public String show500() {
        return "error/500";
    }

    @RequestMapping("/error/404")
    public String show404() {
        return "error/404";
    }

    @RequestMapping({"/error/403", "/error/accessDeniedError", "/error/invalidCsrfTokenError"})
    public String show403() {
        return "error/403";
    }

}
