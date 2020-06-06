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

package e2e.page;

import org.openqa.selenium.By;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.support.ui.ExpectedConditions;
import org.openqa.selenium.support.ui.WebDriverWait;

import java.time.Duration;

public class SignupComponent {

    private final WebDriver webDriver;
    private final WebDriverWait wait;
    private final ResidentKeyRequirementDialog residentKeyRequirementDialog;

    public SignupComponent(WebDriver webDriver) {
        this.webDriver = webDriver;
        this.wait = new WebDriverWait(webDriver, Duration.ofSeconds(5));
        this.residentKeyRequirementDialog = new ResidentKeyRequirementDialog(webDriver);
    }

    public void navigate() {
        webDriver.navigate().to("http://localhost:8080/angular/signup");
    }

    public void setFirstname(String value) {
        webDriver.findElement(By.id("firstname")).sendKeys(value);
    }

    public void setLastname(String value) {
        webDriver.findElement(By.id("lastname")).sendKeys(value);
    }

    public void setUsername(String value) {
        webDriver.findElement(By.id("username")).sendKeys(value);
    }

    public void setPassword(String value) {
        webDriver.findElement(By.id("password")).sendKeys(value);
    }

    public void waitRegisterClickable() {
        wait.until(ExpectedConditions.elementToBeClickable(webDriver.findElement(By.id("register"))));
    }

    public void clickRegister() {
        webDriver.findElement(By.id("register")).click();
    }

    public void clickAddAuthenticator() {
        webDriver.findElement(By.id("addAuthenticator")).click();
    }

    public ResidentKeyRequirementDialog getResidentKeyRequirementDialog() {
        return residentKeyRequirementDialog;
    }
}
