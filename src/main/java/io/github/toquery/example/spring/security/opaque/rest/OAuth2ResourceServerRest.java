/*
 * Copyright 2020 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.github.toquery.example.spring.security.opaque.rest;

import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.server.resource.authentication.BearerTokenAuthentication;
import org.springframework.security.oauth2.server.resource.introspection.OAuth2IntrospectionAuthenticatedPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * OAuth2 Controller that access the JWT.
 *
 * @author Josh Cummings
 */
@RestController
public class OAuth2ResourceServerRest {

	@GetMapping("/")
	public String index(@AuthenticationPrincipal OAuth2IntrospectionAuthenticatedPrincipal auth2IntrospectionAuthenticatedPrincipal, BearerTokenAuthentication authentication) {
		return String.format("Hello, %s and %s !", auth2IntrospectionAuthenticatedPrincipal.getName(), authentication.getName());
	}

	@GetMapping("/message")
	public String message() {
		return "secret message";
	}

}
