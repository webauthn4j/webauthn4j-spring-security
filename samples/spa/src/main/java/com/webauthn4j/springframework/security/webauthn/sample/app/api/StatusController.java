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

package com.webauthn4j.springframework.security.webauthn.sample.app.api;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RequestMapping("/api/status")
@RestController
public class StatusController {

    @RequestMapping("/200")
    public ResponseEntity<String> status200() {
        return new ResponseEntity<>(HttpStatus.OK);
    }

    @RequestMapping("/401")
    public ResponseEntity<String> status401() {
        return new ResponseEntity<>(HttpStatus.UNAUTHORIZED);
    }

    @RequestMapping("/403")
    public ResponseEntity<String> status403() {
        return new ResponseEntity<>(HttpStatus.FORBIDDEN);
    }

}
