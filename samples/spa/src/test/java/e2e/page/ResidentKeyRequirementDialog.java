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

public class ResidentKeyRequirementDialog {

    private final WebDriver webDriver;

    public ResidentKeyRequirementDialog(WebDriver webDriver) {
        this.webDriver = webDriver;
    }

    public void clickYes() {
        webDriver.findElement(By.id("resident-key-requirement-dialog-yes")).click();
    }

    public void clickNo() {
        webDriver.findElement(By.id("resident-key-requirement-dialog-no")).click();
    }

}
