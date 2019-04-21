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

package net.sharplab.springframework.security.webauthn.sample.app.security;

import com.webauthn4j.data.extension.AbstractExtensionInput;
import com.webauthn4j.data.extension.client.AuthenticationExtensionClientInput;
import com.webauthn4j.data.extension.client.RegistrationExtensionClientInput;

import java.io.Serializable;

public class ExampleExtensionClientInput extends AbstractExtensionInput<Serializable>
        implements RegistrationExtensionClientInput<Serializable>, AuthenticationExtensionClientInput<Serializable> {

    public static final String ID = "example.extension";

    public ExampleExtensionClientInput(String value) {
        super(value);
    }

    public ExampleExtensionClientInput(Boolean value) {
        super(value);
    }

    @Override
    public String getIdentifier() {
        return ID;
    }

}
