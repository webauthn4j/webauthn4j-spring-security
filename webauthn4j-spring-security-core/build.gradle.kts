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

group = "com.webauthn4j"
version = "${rootProject.extra["webAuthn4JSpringSecurityVersion"]}"

description = "WebAuthn4J Spring Security Core library"

dependencies {
    // WebAuthn4J
    api(libs.webauthn4j.core)
    api(libs.webauthn4j.metadata)

    // Spring Security
    api("org.springframework.security:spring-security-core")
    api("org.springframework.security:spring-security-config")
    api("org.springframework.security:spring-security-web")

    // Spring Framework
    api("org.springframework:spring-core")
    api("org.springframework:spring-context")
    api("org.springframework:spring-web")
    implementation("org.springframework:spring-aop")
    implementation("org.springframework:spring-jdbc")

    api("jakarta.servlet:jakarta.servlet-api")
    implementation("org.slf4j:slf4j-api")

    implementation("com.fasterxml.jackson.core:jackson-databind")
    implementation("com.fasterxml.jackson.dataformat:jackson-dataformat-cbor")

    //Test
    testImplementation(libs.webauthn4j.test)
    testImplementation("org.projectlombok:lombok")
    testImplementation("org.springframework:spring-webmvc")
    testImplementation("org.springframework.boot:spring-boot-starter-test")
    testImplementation("org.springframework.security:spring-security-test")
    testImplementation("com.h2database:h2")
    testImplementation("junit:junit")
    testImplementation("org.mockito:mockito-core")
    testImplementation("org.assertj:assertj-core")
}
