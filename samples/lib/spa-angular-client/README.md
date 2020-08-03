# WebAuthn4J Spring Security Sample SPA Angular Client

WebAuthn4J Spring Security Sample SPA Angular Client is a client (frontend) module for WebAuthn4J Spring Security Sample SPA based on Angular.

## Build

WebAuthn4J Spring Security Sample SPA Angular Client uses a Gradle based build system.
In the instructions below, `gradlew` is invoked from the root of the source tree and serves as a cross-platform,
self-contained bootstrap mechanism for the build.

Run `./gradlew samples/lib/spa-angular-client:jar` to build the project. 

## Running unit tests

Run `./gradelew samples/lib/spa-angular-client:test` to execute the unit tests via [Karma](https://karma-runner.github.io).

## Running end-to-end tests

Run `./gradelew samples/lib/spa-angular-client:npm_run_e2e` to execute the end-to-end tests via [Protractor](http://www.protractortest.org/).

## Update NPM dependencies

Run `./gradelew samples/lib/spa-angular-client:npm_run_update` to update NPM dependencies.
