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

import org.asciidoctor.gradle.jvm.AsciidoctorTask

plugins {
    id("java-library")
    id("signing")
    id("maven-publish")
    id("jacoco")

    id(libs.plugins.asciidoctor.get().pluginId) version libs.versions.asciidoctor
    id(libs.plugins.sonarqube.get().pluginId) version libs.versions.sonarqube
}

allprojects{
    group = "com.webauthn4j"
    version = "${project.property("webAuthn4JSpringSecurityVersion")}"
}

repositories {
    mavenCentral()
}

subprojects {
    apply(plugin = "java-library")
    apply(plugin = "jacoco")
    apply(plugin = "signing")
    apply(plugin = "maven-publish")

    tasks.withType<JavaCompile> {
        options.compilerArgs.addAll(listOf(
            "-Xlint:unchecked",
            "-Xlint:cast",
            "-Xlint:classfile",
            "-Xlint:dep-ann",
            "-Xlint:divzero",
            "-Xlint:fallthrough",
            "-Xlint:overrides",
            "-Xlint:rawtypes",
            "-Xlint:static",
            "-Xlint:deprecation",
            "-Werror"
        ))
    }

    tasks.withType<Javadoc> {
        options {
            this as StandardJavadocDocletOptions
            charSet = "UTF-8"
            encoding = "UTF-8"
        }
    }

    val sourcesJar by tasks.registering(Jar::class) {
        archiveClassifier.set("sources")
        from(project.the<SourceSetContainer>()["main"].allSource)
        dependsOn(tasks.named("classes"))
    }

    val javadocJar by tasks.registering(Jar::class) {
        archiveClassifier.set("javadoc")
        from(tasks.named<Javadoc>("javadoc"))
    }

    artifacts {
        add("archives", sourcesJar)
        add("archives", javadocJar)
    }

    tasks.named<JacocoReport>("jacocoTestReport") {
        reports {
            xml.required.set(true)
        }
    }

    fun getVariable(envName: String, propertyName: String): String?{
        return if (System.getenv(envName) != null && System.getenv(envName).isNotEmpty()) {
            System.getenv(envName)
        } else if (project.hasProperty(propertyName)) {
            project.property(propertyName) as String?
        } else {
            null
        }
    }

    val githubUrl = "https://github.com/webauthn4j/webauthn4j-spring-security"
    val mavenCentralUser = getVariable("MAVEN_CENTRAL_USER", "mavenCentralUser")
    val mavenCentralPassword = getVariable("MAVEN_CENTRAL_PASSWORD", "mavenCentralPassword")
    val pgpSigningKey = getVariable("PGP_SIGNING_KEY", "pgpSigningKey")
    val pgpSigningKeyPassphrase = getVariable("PGP_SIGNING_KEY_PASSPHRASE", "pgpSigningKeyPassphrase")



    configure<PublishingExtension> {
        publications {
            create<MavenPublication>("standard") {
                from(components["java"])
                artifact(sourcesJar.get())
                artifact(javadocJar.get())

                // "Resolved versions" strategy is used to define dependency version because WebAuthn4J use dependencyManagement (BOM) feature
                // to define its dependency versions. Without "Resolved versions" strategy, version will not be exposed
                // to dependencies.dependency.version in POM file, and it cause warning in the library consumer environment.
                versionMapping {
                    usage("java-api") {
                        fromResolutionOf("runtimeClasspath")
                    }
                    usage("java-runtime") {
                        fromResolutionResult()
                    }
                }

                pom {
                    name.set(project.name)
                    // description.set(project.description) // TODO: this doesn't work. to be fixed. https://github.com/gradle/gradle/issues/12259
                    url.set(githubUrl)
                    licenses {
                        license {
                            name.set("The Apache Software License, Version 2.0")
                            url.set("http://www.apache.org/license/LICENSE-2.0.txt")
                            distribution.set("repo")
                        }
                    }
                    developers {
                        developer {
                            id.set("ynojima")
                            name.set("Yoshikazu Nojima")
                            email.set("mail@ynojima.net")
                        }
                    }
                    scm {
                        url.set(githubUrl)
                    }
                }

                pom.withXml {
                    asNode().appendNode("description", project.description) // workaround for https://github.com/gradle/gradle/issues/12259
                }
            }
        }

        repositories {
            maven {
                name = "mavenCentral"
                url = uri("https://oss.sonatype.org/service/local/staging/deploy/maven2")
                credentials {
                    username = mavenCentralUser
                    password = mavenCentralPassword
                }
            }
            maven {
                name = "snapshot"
                url = uri("https://oss.sonatype.org/content/repositories/snapshots")
                credentials {
                    username = mavenCentralUser
                    password = mavenCentralPassword
                }
            }
        }
    }

    configure<SigningExtension> {
        useInMemoryPgpKeys(pgpSigningKey, pgpSigningKeyPassphrase)
        sign(extensions.getByType<PublishingExtension>().publications["standard"])
    }

    tasks.withType<Sign> {
        onlyIf { pgpSigningKey != null && pgpSigningKeyPassphrase != null }
    }

    val webAuthn4JSpringSecurityVersion = project.property("webAuthn4JSpringSecurityVersion") as String
    tasks.named("publishStandardPublicationToSnapshotRepository") {
        onlyIf { webAuthn4JSpringSecurityVersion.endsWith("-SNAPSHOT") }
    }

    tasks.named("publishStandardPublicationToMavenCentralRepository") {
        onlyIf { !webAuthn4JSpringSecurityVersion.endsWith("-SNAPSHOT") }
    }

    java {
        sourceCompatibility = JavaVersion.VERSION_17
    }

    tasks.withType<JavaCompile> {
        options.compilerArgs.addAll(listOf("-Xlint:unchecked", "-Werror"))
    }

    repositories {
        mavenCentral()
        maven { url = uri("https://oss.sonatype.org/content/repositories/snapshots") }
        maven { url = uri("https://jitpack.io") }
    }

    dependencies {

        // BOM
        implementation(platform(rootProject.libs.spring.boot.dependencies))
        implementation (platform(rootProject.libs.spring.security.bom))
    }
}

tasks.register("updateVersionsInDocuments") {
    group = "documentation"
    val regex = "<webauthn4j-spring-security\\.version>.*</webauthn4j-spring-security\\.version>"
    val latestReleasedWebAuthn4JSpringSecurityVersion = project.property("latestReleasedWebAuthn4JSpringSecurityVersion")
    val replacement = "<webauthn4j-spring-security\\.version>$latestReleasedWebAuthn4JSpringSecurityVersion</webauthn4j-spring-security.version>"

    val files = listOf(
        file("README.md"),
        file("docs/src/reference/asciidoc/en/introduction.adoc"),
        file("docs/src/reference/asciidoc/ja/introduction.adoc")
    )
    files.forEach { file ->
        val updated = file.readText(Charsets.UTF_8).replace(regex.toRegex(), replacement)
        file.writeText(updated, Charsets.UTF_8)
    }
}

tasks.register<JavaExec>("generateReleaseNote") {
    group = "documentation"
    classpath = files("gradle/lib/github-release-notes-generator.jar")

    val latestReleasedWebAuthn4JSpringSecurityVersion = project.property("latestReleasedWebAuthn4JSpringSecurityVersion")
    args(
        latestReleasedWebAuthn4JSpringSecurityVersion,
        file("build/release-note.md").absolutePath,
        "--spring.config.location=file:" + file("github-release-notes-generator.yml").absolutePath
    )
}

tasks.register<AsciidoctorTask>("generateReferenceJA") {
    group = "documentation"
    baseDirFollowsSourceDir()
    setSourceDir(file("docs/src/reference/asciidoc/ja"))
    setOutputDir(file("build/docs/asciidoc/ja"))
    options(mapOf("eruby" to "erubis"))

    attributes(mapOf(
        "docinfo" to "",
        "copycss" to "",
        "icons" to "font",
        "source-highlighter" to "prettify",
        "sectanchors" to "",
        "toc2" to "",
        "idprefix" to "",
        "idseparator" to "-",
        "doctype" to "book",
        "numbered" to "",
        "revnumber" to "${project.property("webAuthn4JSpringSecurityVersion")}"
    ))
}

tasks.register<AsciidoctorTask>("generateReferenceEN") {
    group = "documentation"
    baseDirFollowsSourceDir()
    setSourceDir(file("docs/src/reference/asciidoc/en"))
    setOutputDir(file("build/docs/asciidoc/en"))
    options(mapOf("eruby" to "erubis"))

    attributes(mapOf(
        "docinfo" to "",
        "copycss" to "",
        "icons" to "font",
        "source-highlighter" to "prettify",
        "sectanchors" to "",
        "toc2" to "",
        "idprefix" to "",
        "idseparator" to "-",
        "doctype" to "book",
        "numbered" to "",
        "revnumber" to "${project.property("webAuthn4JSpringSecurityVersion")}"
    ))
}

sonarqube {
    properties {
        property("sonar.projectKey", "webauthn4j-spring-security")
        property("sonar.issue.ignore.multicriteria", "e1,e2,e3")
        property("sonar.issue.ignore.multicriteria.e1.ruleKey", "java:S110")
        property("sonar.issue.ignore.multicriteria.e1.resourceKey", "**/*.java")
        property("sonar.issue.ignore.multicriteria.e2.ruleKey", "java:S1452")
        property("sonar.issue.ignore.multicriteria.e2.resourceKey", "**/*.java")
        property("sonar.issue.ignore.multicriteria.e3.ruleKey", "kotlin:S6474")
        property("sonar.issue.ignore.multicriteria.e3.resourceKey", "**/*.kts")
    }
}
