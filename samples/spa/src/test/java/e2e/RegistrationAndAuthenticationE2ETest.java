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

import com.webauthn4j.springframework.security.authenticator.WebAuthnAuthenticatorService;
import com.webauthn4j.springframework.security.webauthn.sample.SampleSPA;
import e2e.page.AuthenticatorLoginComponent;
import e2e.page.PasswordLoginComponent;
import e2e.page.ProfileComponent;
import e2e.page.SignupComponent;
import io.github.bonigarcia.wdm.WebDriverManager;
import org.junit.After;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.chrome.ChromeDriver;
import org.openqa.selenium.chrome.ChromeOptions;
import org.openqa.selenium.support.ui.ExpectedConditions;
import org.openqa.selenium.support.ui.WebDriverWait;
import org.openqa.selenium.virtualauthenticator.HasVirtualAuthenticator;
import org.openqa.selenium.virtualauthenticator.VirtualAuthenticatorOptions;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.junit4.SpringRunner;

import java.time.Duration;

import static org.assertj.core.api.Assertions.assertThat;

@RunWith(SpringRunner.class)
@SpringBootTest(classes = SampleSPA.class, webEnvironment = SpringBootTest.WebEnvironment.DEFINED_PORT)
public class RegistrationAndAuthenticationE2ETest {

    private WebDriver driver;
    private WebDriverWait wait;

    @Autowired
    private WebAuthnAuthenticatorService webAuthnAuthenticatorService;

    @BeforeClass
    public static void setupClassTest() {
        WebDriverManager.chromedriver().setup();
    }

    @Before
    public void setupTest() {
        ChromeOptions chromeOptions = new ChromeOptions();
        chromeOptions.addArguments("--headless=new");
        chromeOptions.addArguments("--remote-allow-origins=*");
        driver = new ChromeDriver(chromeOptions);
        wait = new WebDriverWait(driver, Duration.ofSeconds(5));
        driver.manage().timeouts().implicitlyWait(Duration.ofSeconds(10));
    }

    @After
    public void teardown() {
        if (driver != null) {
            driver.quit();
        }
    }

    @Test
    public void test() {

        VirtualAuthenticatorOptions options = new VirtualAuthenticatorOptions();
        ((HasVirtualAuthenticator) driver).addVirtualAuthenticator(options);

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

        wait.until(ExpectedConditions.urlToBe("http://localhost:8080/angular/login"));
        long counterValueAtRegistrationPhase = webAuthnAuthenticatorService.loadAuthenticatorsByUserPrincipal("john.doe@example.com").get(0).getCounter();

        // Password authentication
        PasswordLoginComponent passwordLoginComponent = new PasswordLoginComponent(driver);
        passwordLoginComponent.setUsername("john.doe@example.com");
        passwordLoginComponent.setPassword("password");
        passwordLoginComponent.clickLogin();

        // 2nd-factor authentication
        AuthenticatorLoginComponent authenticatorLoginComponent = new AuthenticatorLoginComponent(driver);
        // nop

        wait.until(ExpectedConditions.urlToBe("http://localhost:8080/angular/profile"));
        long counterValueAtAuthenticationPhase = webAuthnAuthenticatorService.loadAuthenticatorsByUserPrincipal("john.doe@example.com").get(0).getCounter();

        assertThat(counterValueAtAuthenticationPhase).isGreaterThan(counterValueAtRegistrationPhase);

        ProfileComponent profileComponent = new ProfileComponent(driver);

    }

}
