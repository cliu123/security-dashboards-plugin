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

import { ILegacyClusterClient, OpenSearchDashboardsRequest } from '../../../../src/core/server';
import { User } from '../auth/user';

export class SecurityClient {
  constructor(private readonly esClient: ILegacyClusterClient) {}

  public async authenticate(request: OpenSearchDashboardsRequest, credentials: any): Promise<User> {
    const authHeader = Buffer.from(`${credentials.username}:${credentials.password}`).toString(
      'base64'
    );
    try {
      const esResponse = await this.esClient
        .asScoped(request)
        .callAsCurrentUser('opensearch_security.authinfo', {
          headers: {
            authorization: `Basic ${authHeader}`,
          },
        });
      return {
        username: credentials.username,
        roles: esResponse.roles,
        backendRoles: esResponse.backend_roles,
        tenants: esResponse.tenants,
        selectedTenant: esResponse.user_requested_tenant,
        credentials,
        proxyCredentials: credentials,
      };
    } catch (error: any) {
      throw new Error(error.message);
    }
  }

  public async authenticateWithHeader(
    request: OpenSearchDashboardsRequest,
    headerName: string,
    headerValue: string,
    whitelistedHeadersAndValues: any = {},
    additionalAuthHeaders: any = {}
  ): Promise<User> {
    try {
      const credentials: any = {
        headerName,
        headerValue,
      };
      const headers: any = {};
      if (headerValue) {
        headers[headerName] = headerValue;
      }

      // cannot get config elasticsearch.requestHeadersWhitelist from kibana.yml file in new platfrom
      // meanwhile, do we really need to save all headers in cookie?
      const esResponse = await this.esClient
        .asScoped(request)
        .callAsCurrentUser('opensearch_security.authinfo', {
          headers,
        });
      return {
        username: esResponse.user_name,
        roles: esResponse.roles,
        backendRoles: esResponse.backend_roles,
        tenants: esResponse.teanats,
        selectedTenant: esResponse.user_requested_tenant,
        credentials,
      };
    } catch (error: any) {
      throw new Error(error.message);
    }
  }

  public async authenticateWithHeaders(
    request: OpenSearchDashboardsRequest,
    additionalAuthHeaders: any = {}
  ): Promise<User> {
    try {
      const esResponse = await this.esClient
        .asScoped(request)
        .callAsCurrentUser('opensearch_security.authinfo', {
          headers: additionalAuthHeaders,
        });
      return {
        username: esResponse.user_name,
        roles: esResponse.roles,
        backendRoles: esResponse.backend_roles,
        tenants: esResponse.tenants,
        selectedTenant: esResponse.user_requested_tenant,
      };
    } catch (error: any) {
      throw new Error(error.message);
    }
  }

  public async authinfo(request: OpenSearchDashboardsRequest, headers: any = {}) {
    try {
      return await this.esClient
        .asScoped(request)
        .callAsCurrentUser('opensearch_security.authinfo', {
          headers,
        });
    } catch (error: any) {
      throw new Error(error.message);
    }
  }

  // Multi-tenancy APIs
  public async getMultitenancyInfo(request: OpenSearchDashboardsRequest) {
    try {
      return await this.esClient
        .asScoped(request)
        .callAsCurrentUser('opensearch_security.multitenancyinfo');
    } catch (error: any) {
      throw new Error(error.message);
    }
  }

  public async getTenantInfoWithInternalUser() {
    try {
      return this.esClient.callAsInternalUser('opensearch_security.tenantinfo');
    } catch (error: any) {
      throw new Error(error.message);
    }
  }

  public async getTenantInfo(request: OpenSearchDashboardsRequest) {
    try {
      return await this.esClient
        .asScoped(request)
        .callAsCurrentUser('opensearch_security.tenantinfo');
    } catch (error: any) {
      throw new Error(error.message);
    }
  }

  public async getSamlHeader(request: OpenSearchDashboardsRequest) {
    return {
      location: 'https://cgliu.onelogin.com/trust/saml2/http-redirect/sso/62513ad7-0fb6-4ef7-8065-c7d48f5ba802?SAMLRequest=fVLLjhoxEPyVke%2FGnjexAIkseSARQAvJIRfk8fSAJY9N3J4k%2B%2FdrhqyyOWQvltWuKleVeoayN1exHMLFPsKPATAkv3tjUYwPczJ4K5xEjcLKHlAEJQ7LLxuRTbi4eheccoa8orzNkIjgg3aWJOvVnOy2Hza7T%2BvtSWacV03bUVmUihZZw2lT5%2BORyrTKedEpknwDj5E7J1EqCiAOsLYYpA1xxLOc8pRm%2BTHLBa9FXn8nySrm0VaGkXUJ4YqCMXU2epg4C8adtZ0o17PgBwzs5j9jNxj10GoPKs7QsSor01y2NeVdU9ECuppOeVVSVbfFtCsbOeUZSfZ%2F2nivbavt%2Be0imjsIxefjcU%2F3u8ORJMuXch6cxaEHfwD%2FUyv4%2Bri5m4%2FejVPSXBwGUVY8ZSd3hSiEwTt2QlCD1%2BFpzMGkQrKY3a5ibMovXvL%2F1XgXa5%2Bx15jZfR%2B20fB6tXdGq6fko%2FO9DP%2FPk07ScaJb2o1QMVi8gtKdhjbGMsb9evAgA8xJLBpIwhb3X%2F9dvMUz',
      requestId: 'ONELOGIN_a2006bdf-a45c-42b0-b730-b731a16304fc'
    }
    
    try {
      // response is expected to be an error
      await this.esClient.asScoped(request).callAsCurrentUser('opensearch_security.authinfo');
    } catch (error: any) {
      console.log("!!!!!!error");
      console.log(error);
      // the error looks like
      // wwwAuthenticateDirective:
      //   '
      //     X-Security-IdP realm="Open Distro Security"
      //     location="https://<your-auth-domain.com>/api/saml2/v1/sso?SAMLRequest=<some-encoded-string>"
      //     requestId="<request_id>"
      //   '

      if (!error.wwwAuthenticateDirective) {
        throw error;
      }

      try {
        const locationRegExp = /location="(.*?)"/;
        const requestIdRegExp = /requestId="(.*?)"/;

        const locationExecArray = locationRegExp.exec(error.wwwAuthenticateDirective);
        const requestExecArray = requestIdRegExp.exec(error.wwwAuthenticateDirective);
        if (locationExecArray && requestExecArray) {
          console.log("22222222 output")
          console.log({
            location: locationExecArray[1],
            requestId: requestExecArray[1],
          });
          return {
            location: locationExecArray[1],
            requestId: requestExecArray[1],
          };
        }
        throw Error('failed parsing SAML config');
      } catch (parsingError: any) {
        console.log(parsingError);
        throw new Error(parsingError);
      }
    }
    throw new Error(`Invalid SAML configuration.`);
  }

  public async authToken(
    requestId: string | undefined,
    samlResponse: any,
    acsEndpoint: any | undefined = undefined
  ) {
    const body = {
      RequestId: requestId,
      SAMLResponse: samlResponse,
      acsEndpoint,
    };
    try {
      return await this.esClient.asScoped().callAsCurrentUser('opensearch_security.authtoken', {
        body,
      });
    } catch (error: any) {
      console.log(error);
      throw new Error('failed to get token');
    }
  }
}
