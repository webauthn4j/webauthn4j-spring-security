/*
 * Copyright 2002-2019 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package e2e;

import e2e.page.AuthenticatorLoginComponent;
import e2e.page.PasswordLoginComponent;
import e2e.page.ProfileComponent;
import e2e.page.SignupComponent;
import org.junit.Test;
import org.openqa.selenium.support.ui.ExpectedConditions;

public class RegistrationAndAuthenticationE2ETest extends E2ETestBase{


    @Test
    public void test() {
        // Registration
        SignupComponent signupComponent = new SignupComponent(driver);
        signupComponent.navigate();
        signupComponent.setFirstname("John");
        signupComponent.setLastname("Doe");
        signupComponent.setUsername("john.doe@example.com");
        signupComponent.setPassword("password");
        signupComponent.clickAddAuthenticator();
        signupComponent.getResidentKeyRequirementDialog().clickNo();
        signupComponent.waitRegisterClickable();
        signupComponent.clickRegister();

        // Password authentication
        wait.until(ExpectedConditions.urlToBe("http://localhost:8080/angular/login"));
        PasswordLoginComponent passwordLoginComponent = new PasswordLoginComponent(driver);
        passwordLoginComponent.setUsername("john.doe@example.com");
        passwordLoginComponent.setPassword("password");
        passwordLoginComponent.clickLogin();

        // 2nd-factor authentication
        AuthenticatorLoginComponent authenticatorLoginComponent = new AuthenticatorLoginComponent(driver);
        // nop

        wait.until(ExpectedConditions.urlToBe("http://localhost:8080/angular/profile"));
        ProfileComponent profileComponent = new ProfileComponent(driver);

    }

//    @Test
//    public void mock_authenticator_test() {
//
//        // Registration
//        SignupComponent signupComponent = new SignupComponent(driver);
//        signupComponent.navigate();
//        signupComponent.doAuthenticator();
//
//        signupComponent.setFirstname("John");
//        signupComponent.setLastname("Doe");
//        signupComponent.setUsername("john.doe@example.com");
//        signupComponent.setPassword("password");
//        signupComponent.clickAddAuthenticator();
//        signupComponent.getResidentKeyRequirementDialog().clickNo();
//        signupComponent.waitRegisterClickable();
//        signupComponent.clickRegister();
//
//        // Password authentication
//        wait.until(ExpectedConditions.urlToBe("http://localhost:8080/angular/login"));
//        PasswordLoginComponent passwordLoginComponent = new PasswordLoginComponent(driver);
//        passwordLoginComponent.setUsername("john.doe@example.com");
//        passwordLoginComponent.setPassword("password");
//        passwordLoginComponent.clickLogin();
//
//        // 2nd-factor authentication
//        AuthenticatorLoginComponent authenticatorLoginComponent = new AuthenticatorLoginComponent(driver);
//        // nop
//
//        wait.until(ExpectedConditions.urlToBe("http://localhost:8080/angular/profile"));
//        ProfileComponent profileComponent = new ProfileComponent(driver);
//
//    }

}
