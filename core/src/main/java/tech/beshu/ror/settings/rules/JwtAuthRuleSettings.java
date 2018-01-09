/*
 *    This file is part of ReadonlyREST.
 *
 *    ReadonlyREST is free software: you can redistribute it and/or modify
 *    it under the terms of the GNU General Public License as published by
 *    the Free Software Foundation, either version 3 of the License, or
 *    (at your option) any later version.
 *
 *    ReadonlyREST is distributed in the hope that it will be useful,
 *    but WITHOUT ANY WARRANTY; without even the implied warranty of
 *    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *    GNU General Public License for more details.
 *
 *    You should have received a copy of the GNU General Public License
 *    along with ReadonlyREST.  If not, see http://www.gnu.org/licenses/
 */
package tech.beshu.ror.settings.rules;

import java.util.Collections;
import java.util.Optional;
import java.util.Set;

import com.google.common.base.Strings;

import tech.beshu.ror.commons.settings.RawSettings;
import tech.beshu.ror.commons.settings.SettingsMalformedException;
import tech.beshu.ror.settings.AuthKeyProviderSettings;
import tech.beshu.ror.settings.RuleSettings;

public class JwtAuthRuleSettings implements RuleSettings, AuthKeyProviderSettings {

  public static final String ATTRIBUTE_NAME = "jwt_auth";
  private static final String SIGNATURE_ALGO = "signature_algo";
  private static final String SIGNATURE_KEY = "signature_key";
  private static final String USER_CLAIM = "user_claim";
  private static final String ROLES_CLAIM = "roles_claim";
  private static final String HEADER_NAME = "header_name";
  private static final String DEFAULT_HEADER_NAME = "Authorization";
  private static final String ROLES = "roles";

  private final byte[] key;
  private final Optional<String> userClaim;
  private final Optional<String> rolesClaim;
  private final Optional<String> algo;
  private final String headerName;
  private final Set<String> roles;

  @SuppressWarnings("unchecked")
  private JwtAuthRuleSettings(String key,  Optional<String> algo, Optional<String> userClaim, Optional<String> rolesClaim, Optional<String> headerName, Optional<Set<?>> roles) {
    if (Strings.isNullOrEmpty(key))
      throw new SettingsMalformedException(
        "Attribute '" + SIGNATURE_KEY + "' shall not evaluate to an empty string");
    this.key = key.getBytes();
    this.algo = algo;
    this.userClaim = userClaim;
    this.rolesClaim = rolesClaim;
    this.headerName = headerName.orElse(DEFAULT_HEADER_NAME);
    this.roles = (Set<String>)(roles.orElse(Collections.emptySet()));
  }

  public static JwtAuthRuleSettings from(RawSettings settings) {
    return new JwtAuthRuleSettings(
      evalPrefixedSignatureKey(ensureString(settings, SIGNATURE_KEY)),
      settings.stringOpt(SIGNATURE_ALGO),
      settings.stringOpt(USER_CLAIM),
      settings.stringOpt(ROLES_CLAIM),
      settings.stringOpt(HEADER_NAME),
      settings.notEmptySetOpt(ROLES)
    );
  }

  private static String ensureString(RawSettings settings, String key) {
    Object value = settings.req(key);
    if (value instanceof String) return (String) value;
    else throw new SettingsMalformedException(
      "Attribute '" + key + "' must be a string; if it looks like a number try adding quotation marks");
  }

  private static String evalPrefixedSignatureKey(String s) {
    if (s.startsWith("text:"))
      return s.substring(5);
    else if (s.startsWith("env:"))
      return System.getenv(s.substring(4));
    else return s;
  }

  public byte[] getKey() {
    return key;
  }

  public Optional<String> getAlgo() {
   return algo;
  }

  public Optional<String> getUserClaim() {
    return userClaim;
  }

  public Optional<String> getRolesClaim() {
    return rolesClaim;
  }

  public String getHeaderName() {
    return headerName;
  }

  public Set<String> getRoles() {
    return roles;
  }

  @Override
  public String getName() {
    return ATTRIBUTE_NAME;
  }
}