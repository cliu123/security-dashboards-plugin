/*
 *   Copyright OpenSearch Contributors
 *
 *   Licensed under the Apache License, Version 2.0 (the "License").
 *   You may not use this file except in compliance with the License.
 *   A copy of the License is located at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *
 *   or in the "license" file accompanying this file. This file is distributed
 *   on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 *   express or implied. See the License for the specific language governing
 *   permissions and limitations under the License.
 */

export const PLUGIN_ID = 'opensearchDashboardsSecurity';
export const PLUGIN_NAME = 'security-dashboards-plugin';

export const APP_ID_LOGIN = 'login';
export const APP_ID_CUSTOMERROR = 'customerror';
export const OPENDISTRO_SECURITY_ANONYMOUS = 'opendistro_security_anonymous';

export const API_PREFIX = '/api/v1';
export const CONFIGURATION_API_PREFIX = 'configuration';
export const API_ENDPOINT_AUTHINFO = API_PREFIX + '/auth/authinfo';
export const API_ENDPOINT_AUTHTYPE = API_PREFIX + '/auth/type';
export const LOGIN_PAGE_URI = '/app/' + APP_ID_LOGIN;
export const CUSTOM_ERROR_PAGE_URI = '/app/' + APP_ID_CUSTOMERROR;
export const API_AUTH_LOGIN = '/auth/login';
export const API_AUTH_LOGOUT = '/auth/logout';
export const OPENID_AUTH_LOGIN = '/auth/openid/login';
export const SAML_AUTH_LOGIN = '/auth/saml/login';
export const ANONYMOUS_AUTH_LOGIN = '/auth/anonymous';
export const SAML_AUTH_LOGIN_WITH_FRAGMENT = '/auth/saml/captureUrlFragment?nextUrl=%2F';

export const OPENID_AUTH_LOGOUT = '/auth/openid/logout';
export const SAML_AUTH_LOGOUT = '/auth/saml/logout';
export const ANONYMOUS_AUTH_LOGOUT = '/auth/anonymous/logout';

export const ERROR_MISSING_ROLE_PATH = '/missing-role';
export const AUTH_HEADER_NAME = 'authorization';
export const AUTH_GRANT_TYPE = 'authorization_code';
export const AUTH_RESPONSE_TYPE = 'code';

export const GLOBAL_TENANT_SYMBOL = '';
export const PRIVATE_TENANT_SYMBOL = '__user__';
export const DEFAULT_TENANT = 'default';
export const GLOBAL_TENANT_RENDERING_TEXT = 'Global';
export const PRIVATE_TENANT_RENDERING_TEXT = 'Private';
export const globalTenantName = 'global_tenant';

export const jwtKey = "6aff3042-1327-4f3d-82f0-40a157ac4464";

export const idpCert = "MIIDzzCCAregAwIBAgIUKizt/svOXO4USLQ3spS2Bn507LYwDQYJKoZIhvcNAQEFBQAwQTEMMAoGA1UECgwDQVdTMRUwEwYDVQQLDAxPbmVMb2dpbiBJZFAxGjAYBgNVBAMMEU9uZUxvZ2luIEFjY291bnQgMB4XDTIzMDExMzIwMTQzNVoXDTI4MDExMzIwMTQzNVowQTEMMAoGA1UECgwDQVdTMRUwEwYDVQQLDAxPbmVMb2dpbiBJZFAxGjAYBgNVBAMMEU9uZUxvZ2luIEFjY291bnQgMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwTX1daRM90aJmDCWTL3Iuj4GvK2nHRNZoLP9dzscbFJNMIQEXdyREHSVnFO18KWDfwX3gOgvcuijJUk+r5XCf1oJueUNhme/Q8eSHQe1TOhOVPXuI9BxMyPupeKfmFelIylTNvUoCQo2A/dJURRN2rjz4pOoCqadOlgm2So//J8I/JiZVO6S1YleAjWY5VYOMJMq8QKBBMKkmxok+reA36lmvi2JtUZWpZVo62XVcjP9+uOONyXo7O3VEu8Vwezex2sXFyCm699G1aeRCtHQ3yKmhf0Rm0D+RgZKnG+9i6aeJFTXluBqOrz6CtXtW0SV2NKIeK36EcMH1unlG4/VMwIDAQABo4G+MIG7MAwGA1UdEwEB/wQCMAAwHQYDVR0OBBYEFKsWx05elVPbItGUYA3SBXVehP7VMHwGA1UdIwR1MHOAFKsWx05elVPbItGUYA3SBXVehP7VoUWkQzBBMQwwCgYDVQQKDANBV1MxFTATBgNVBAsMDE9uZUxvZ2luIElkUDEaMBgGA1UEAwwRT25lTG9naW4gQWNjb3VudCCCFCos7f7LzlzuFEi0N7KUtgZ+dOy2MA4GA1UdDwEB/wQEAwIHgDANBgkqhkiG9w0BAQUFAAOCAQEAh0Kg8BQrOuWO30A6Qj+VL2Ke0/Y96hgdjYxk4zcIwZcIxfb5U733ftF2H0r8RKBYNrWpEmPwa4RnaTqwRaY/pahZ7kznzgMVUMhT9QZe4uNDLu5HgzAuOdhpYk2qv6+GYqcbMNtKPEtTjp0/KwMntgBkn9dPBSiydqojtwh0i2e2rhFh4gBDvuXdHZCcOWCKYm24IOoEI41Q4JIu1jAk6LM3jErcZdx+Lqa9rvSn6jdC6/jwhR1anqqLU9qGIjN99640z/JIOdK8wPei2veLpZbKIDtG/iaSNkdrFhEE1WNXTnnPImQNVgvIT9QdyOLLdzuQ25G3Qraj47JEMm0Xmw==";

export enum AuthType {
  BASIC = 'basicauth',
  OPEN_ID = 'openid',
  JWT = 'jwt',
  SAML = 'saml',
  PROXY = 'proxy',
  ANONYMOUS = 'anonymous',
}

/**
 * A valid resource name should not containing percent sign (%) as they raise url injection issue.
 * And also should not be empty.
 * @param resourceName resource name to be validated
 */
export function isValidResourceName(resourceName: string): boolean {
  // see: https://javascript.info/regexp-unicode
  const exp = new RegExp('[\\p{C}%]', 'u');
  return !exp.test(resourceName) && resourceName.length > 0;
}

export function isPrivateTenant(selectedTenant: string | null) {
  return selectedTenant !== null && selectedTenant === PRIVATE_TENANT_SYMBOL;
}

export function isRenderingPrivateTenant(selectedTenant: string | null) {
  return selectedTenant !== null && selectedTenant?.startsWith(PRIVATE_TENANT_SYMBOL);
}

export function isGlobalTenant(selectedTenant: string | null) {
  return selectedTenant !== null && selectedTenant === GLOBAL_TENANT_SYMBOL;
}
