/*
 *    Copyright 2002-2019 the original author or authors.
 *
 *    Licensed under the Apache License, Version 2.0 (the "License");
 *    you may not use this file except in compliance with the License.
 *    You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS,
 *    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *    See the License for the specific language governing permissions and
 *    limitations under the License.
 */

package net.sharplab.springframework.security.fido.server.endpoint;

public abstract class ServerResponseBase implements ServerResponse {

    private Status status;
    private String errorMessage;

    public ServerResponseBase(Status status, String errorMessage) {
        this.status = status;
        this.errorMessage = errorMessage;
    }

    public ServerResponseBase() {
        this.status = Status.OK;
        this.errorMessage = "";
    }

    @Override
    public Status getStatus() {
        return status;
    }

    @Override
    public String getErrorMessage() {
        return errorMessage;
    }

}
