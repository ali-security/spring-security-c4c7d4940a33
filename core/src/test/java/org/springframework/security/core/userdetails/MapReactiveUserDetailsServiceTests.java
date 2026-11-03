/*
 * Copyright 2002-2017 the original author or authors.
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
package org.springframework.security.core.userdetails;


import static org.assertj.core.api.Assertions.assertThat;

import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Locale;

import org.junit.Test;

import reactor.core.publisher.Mono;

public class MapReactiveUserDetailsServiceTests {
	private static final UserDetails USER_DETAILS = User.withUsername("user")
			.password("password")
			.roles("USER")
			.build();

	private MapReactiveUserDetailsService users = new MapReactiveUserDetailsService(Arrays.asList(USER_DETAILS));

	@Test(expected = IllegalArgumentException.class)
	public void constructorNullUsers() {
		Collection<UserDetails> users = null;
		new MapReactiveUserDetailsService(users);
	}

	@Test(expected = IllegalArgumentException.class)
	public void constructorEmptyUsers() {
		Collection<UserDetails> users = Collections.emptyList();
		new MapReactiveUserDetailsService(users);
	}

	@Test
	public void findByUsernameWhenFoundThenReturns() {
		assertThat((users.findByUsername(USER_DETAILS.getUsername()).block())).isEqualTo(USER_DETAILS);
	}

	@Test
	public void findByUsernameWhenDifferentCaseThenReturns() {
		assertThat((users.findByUsername("uSeR").block())).isEqualTo(USER_DETAILS);
	}

	@Test
	public void findByUsernameWhenDefaultLocaleIsTurkishThenUsernameKeyIsLocaleIndependent() {
		Locale defaultLocale = Locale.getDefault();
		try {
			Locale.setDefault(new Locale("tr", "TR"));
			UserDetails admin = User.withUsername("ADMIN")
					.password("password")
					.roles("ADMIN")
					.build();
			MapReactiveUserDetailsService service = new MapReactiveUserDetailsService(admin);
			assertThat(service.findByUsername("admin").block()).isEqualTo(admin);
			// a different username (dotless i) must not resolve to the ADMIN account
			assertThat(service.findByUsername("admın").block()).isNull();
		}
		finally {
			Locale.setDefault(defaultLocale);
		}
	}

	@Test
	public void findByUsernameWhenClearCredentialsThenFindByUsernameStillHasCredentials() {
		User foundUser = users.findByUsername(USER_DETAILS.getUsername()).cast(User.class).block();
		assertThat(foundUser.getPassword()).isNotEmpty();
		foundUser.eraseCredentials();
		assertThat(foundUser.getPassword()).isNull();

		foundUser = users.findByUsername(USER_DETAILS.getUsername()).cast(User.class).block();
		assertThat(foundUser.getPassword()).isNotEmpty();
	}

	@Test
	public void findByUsernameWhenNotFoundThenEmpty() {
		assertThat((users.findByUsername("notfound"))).isEqualTo(Mono.empty());
	}

	@Test
	public void updatePassword() {
		users.updatePassword(USER_DETAILS, "new").block();
		assertThat(users.findByUsername(USER_DETAILS.getUsername()).block().getPassword()).isEqualTo("new");
	}
}
