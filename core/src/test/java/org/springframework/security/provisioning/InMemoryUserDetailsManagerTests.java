/*
 * Copyright 2002-2018 the original author or authors.
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

package org.springframework.security.provisioning;

import java.util.Locale;
import java.util.Properties;

import org.junit.Test;
import org.springframework.security.core.userdetails.PasswordEncodedUser;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import static org.assertj.core.api.Assertions.*;

/**
 * @author Rob Winch
 * @since 5.1
 */
public class InMemoryUserDetailsManagerTests {
	private final UserDetails user = PasswordEncodedUser.user();

	private InMemoryUserDetailsManager manager = new InMemoryUserDetailsManager(this.user);

	@Test
	public void changePassword() {
		String newPassword = "newPassword";
		this.manager.updatePassword(this.user, newPassword);
		assertThat(this.manager.loadUserByUsername(this.user.getUsername()).getPassword()).isEqualTo(newPassword);
	}

	@Test
	public void changePasswordWhenUsernameIsNotInLowercase() {
		UserDetails userNotLowerCase = User.withUserDetails(PasswordEncodedUser.user())
				.username("User")
				.build();

		String newPassword = "newPassword";
		this.manager.updatePassword(userNotLowerCase, newPassword);
		assertThat(this.manager.loadUserByUsername(userNotLowerCase.getUsername()).getPassword()).isEqualTo(newPassword);
	}

	@Test
	public void loadUserByUsernameWhenDefaultLocaleIsTurkishThenUsernameKeyIsLocaleIndependent() {
		Locale defaultLocale = Locale.getDefault();
		try {
			Locale.setDefault(new Locale("tr", "TR"));
			UserDetails admin = User.withUserDetails(PasswordEncodedUser.admin())
					.username("ADMIN")
					.build();
			InMemoryUserDetailsManager manager = new InMemoryUserDetailsManager(admin);
			assertThat(manager.userExists("admin")).isTrue();
			assertThat(manager.loadUserByUsername("admin").getUsername()).isEqualTo("ADMIN");
			// a different username (dotless i) must not resolve to the ADMIN account
			assertThat(manager.userExists("admın")).isFalse();
			assertThatThrownBy(() -> manager.loadUserByUsername("admın"))
					.isInstanceOf(UsernameNotFoundException.class);
		}
		finally {
			Locale.setDefault(defaultLocale);
		}
	}

	@Test
	public void constructorWhenPropertiesDisabledAndDefaultLocaleIsTurkishThenUserIsDisabled() {
		Locale defaultLocale = Locale.getDefault();
		try {
			Locale.setDefault(new Locale("tr", "TR"));
			Properties properties = new Properties();
			properties.setProperty("bob", "password,DISABLED,ROLE_USER");
			InMemoryUserDetailsManager manager = new InMemoryUserDetailsManager(properties);
			UserDetails bob = manager.loadUserByUsername("bob");
			assertThat(bob.isEnabled()).isFalse();
			assertThat(bob.getAuthorities()).extracting("authority").containsOnly("ROLE_USER");
		}
		finally {
			Locale.setDefault(defaultLocale);
		}
	}
}
