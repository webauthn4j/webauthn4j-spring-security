package net.sharplab.springframework.security.webauthn.sample.app.api;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationTrustResolver;
import org.springframework.security.authentication.MFATokenEvaluator;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RequestMapping("/api/auth")
@RestController
public class AuthController {

    @Autowired
    private MFATokenEvaluator mfaTokenEvaluator;

    @Autowired
    private AuthenticationTrustResolver trustResolver;

    @RequestMapping("/status")
    public AuthResponse status(){
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        AuthStatus status;
        if(authentication == null){
            status = AuthStatus.Anonymous;
        }
        else if(mfaTokenEvaluator.isMultiFactorAuthentication(authentication)){
            status = AuthStatus.PartiallyAuthenticated;
        }
        else if(trustResolver.isAnonymous(authentication)){
            status = AuthStatus.Anonymous;
        }
        else {
            status = AuthStatus.Authenticated;
        }
        return new AuthResponse(status);
    }

}
