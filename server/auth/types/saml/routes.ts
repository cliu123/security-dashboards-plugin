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

import { schema } from '@osd/config-schema';
import {
  IRouter,
  SessionStorageFactory,
  OpenSearchDashboardsRequest,
} from '../../../../../../src/core/server';
import { SecuritySessionCookie } from '../../../session/security_cookie';
import { SecurityPluginConfigType } from '../../..';
import { SecurityClient } from '../../../backend/opensearch_security_client';
import { CoreSetup } from '../../../../../../src/core/server';
import { validateNextUrl } from '../../../utils/next_url';
import { AuthType, SAML_AUTH_LOGIN, SAML_AUTH_LOGOUT } from '../../../../common';
import { compileSchema } from 'ajv/dist/compile';
import { XMLParser } from "fast-xml-parser";

export class SamlAuthRoutes {
  constructor(
    private readonly router: IRouter,
    // @ts-ignore: unused variable
    private readonly config: SecurityPluginConfigType,
    private readonly sessionStorageFactory: SessionStorageFactory<SecuritySessionCookie>,
    private readonly securityClient: SecurityClient,
    private readonly coreSetup: CoreSetup
  ) {}

  public setupRoutes() {
    this.router.get(
      {
        path: SAML_AUTH_LOGIN,
        validate: {
          query: schema.object({
            nextUrl: schema.maybe(
              schema.string({
                validate: validateNextUrl,
              })
            ),
          }),
        },
        options: {
          authRequired: false,
        },
      },
      async (context, request, response) => {
        if (request.auth.isAuthenticated) {
          return response.redirected({
            headers: {
              location: `${this.coreSetup.http.basePath.serverBasePath}/app/opensearch-dashboards`,
            },
          });
        }

        try {
          const samlHeader = await this.securityClient.getSamlHeader(request);
          // const { nextUrl = '/' } = request.query;
          const cookie: SecuritySessionCookie = {
            saml: {
              nextUrl: request.query.nextUrl,
              requestId: samlHeader.requestId,
            },
          };
          this.sessionStorageFactory.asScoped(request).set(cookie);
          return response.redirected({
            headers: {
              location: samlHeader.location,
            },
          });
        } catch (error) {
          context.security_plugin.logger.error(`Failed to get saml header: ${error}`);
          return response.internalError(); // TODO: redirect to error page?
        }
      }
    );

    this.router.post(
      {
        path: `/_opendistro/_security/saml/acs`,
        validate: {
          body: schema.any(),
        },
        options: {
          authRequired: false,
        },
      },
      async (context, request, response) => {
        let requestId: string = '';
        let nextUrl: string = '/';
        try {
          const cookie = await this.sessionStorageFactory.asScoped(request).get();
          if (cookie) {
            requestId = cookie.saml?.requestId || '';
            nextUrl =
              cookie.saml?.nextUrl ||
              `${this.coreSetup.http.basePath.serverBasePath}/app/opensearch-dashboards`;
          }
          if (!requestId) {
            return response.badRequest({
              body: 'Invalid requestId',
            });
          }
        } catch (error) {
          context.security_plugin.logger.error(`Failed to parse cookie: ${error}`);
          return response.badRequest();
        }

        try {
          const SAML = require("saml-encoder-decoder-js");
          const xmlParser = new XMLParser();
          const token = request.body.SAMLResponse;
          // TODO: 
          // - Validate SAML Response 
          // - Set the SAML Response expiry in cookie
          // - Consider how identiy info updates in IDP are synced with SP(Just in time/Real Time updates)
          SAML.decodeSamlPost(token, function(err: string | undefined, xml: any) {
              if (err) {
                  throw new Error(err);
              }
              const jsonObj = xmlParser.parse(xml);
              const username = jsonObj["samlp:Response"]["saml:Assertion"]["saml:Subject"]["saml:NameID"];
          });
          

          // const credentials = await this.securityClient.authToken(
          //   requestId,
          //   request.body.SAMLResponse,
          //   undefined
          // );
          // const user = await this.securityClient.authenticateWithHeader(
          //   request,
          //   'authorization',
          //   credentials.authorization
          // );

          let expiryTime = Date.now() + this.config.session.ttl;
          // const [headerEncoded, payloadEncoded, signature] = credentials.authorization.split('.');
          // if (!payloadEncoded) {
          //   context.security_plugin.logger.error('JWT token payload not found');
          // }
          // const tokenPayload = JSON.parse(Buffer.from(payloadEncoded, 'base64').toString());

          // if (tokenPayload.exp) {
          //   expiryTime = parseInt(tokenPayload.exp, 10) * 1000;
          // }
          // const cookie: SecuritySessionCookie = {
          //   username: user.username,
          //   credentials: {
          //     authHeaderValue: credentials.authorization,
          //   },
          //   authType: AuthType.SAML, // TODO: create constant
          //   expiryTime,
          // };
          // console.log("######cookie");
          // console.log(cookie);
          const cookie: SecuritySessionCookie = {
            username: "cgliu@amazon.com",
            credentials: {
              authHeaderValue: "bearer eyJhbGciOiJIUzUxMiJ9.eyJuYmYiOjE2NzQ1NTAxMjYsImV4cCI6MTY3NDYzNjUyNiwic3ViIjoiY2dsaXVAYW1hem9uLmNvbSIsInNhbWxfbmlmIjoiZW1haWwiLCJzYW1sX3NpIjoiXzhjYjUwOGI5LWNhZTItNDgyYS05YTEyLTFiOTY3MTA4Y2MyNSIsInJvbGVzIjpbImFkbWluIl19.LwkAcuq2ReiUxidkB4sx3BHg_4Vs1hsSOn--CyRghiZ2SouB7Y2eTwLr41-Nv1l_1lQYGY1JichHX06fvHC22w",
            },
            authType: AuthType.SAML, // TODO: create constant
            expiryTime,
          };
          this.sessionStorageFactory.asScoped(request).set(cookie);
          return response.redirected({
            headers: {
              location: nextUrl,
            },
          });
        } catch (error) {
          context.security_plugin.logger.error(
            `SAML SP initiated authentication workflow failed: ${error}`
          );
        }

        return response.internalError();
      }
    );

    this.router.post(
      {
        path: `/_opendistro/_security/saml/acs/idpinitiated`,
        validate: {
          body: schema.any(),
        },
        options: {
          authRequired: false,
        },
      },
      async (context, request, response) => {
        const acsEndpoint = `${this.coreSetup.http.basePath.serverBasePath}/_opendistro/_security/saml/acs/idpinitiated`;
        try {
          const credentials = await this.securityClient.authToken(
            undefined,
            request.body.SAMLResponse,
            acsEndpoint
          );
          const user = await this.securityClient.authenticateWithHeader(
            request,
            'authorization',
            credentials.authorization
          );

          let expiryTime = Date.now() + this.config.session.ttl;
          const [headerEncoded, payloadEncoded, signature] = credentials.authorization.split('.');
          if (!payloadEncoded) {
            context.security_plugin.logger.error('JWT token payload not found');
          }
          const tokenPayload = JSON.parse(Buffer.from(payloadEncoded, 'base64').toString());
          if (tokenPayload.exp) {
            expiryTime = parseInt(tokenPayload.exp, 10) * 1000;
          }

          const cookie: SecuritySessionCookie = {
            username: user.username,
            credentials: {
              authHeaderValue: credentials.authorization,
            },
            authType: AuthType.SAML, // TODO: create constant
            expiryTime,
          };
          this.sessionStorageFactory.asScoped(request).set(cookie);
          return response.redirected({
            headers: {
              location: `${this.coreSetup.http.basePath.serverBasePath}/app/opensearch-dashboards`,
            },
          });
        } catch (error) {
          context.security_plugin.logger.error(
            `SAML IDP initiated authentication workflow failed: ${error}`
          );
        }
        return response.internalError();
      }
    );

    this.router.get(
      {
        path: SAML_AUTH_LOGOUT,
        validate: false,
      },
      async (context, request, response) => {
        try {
          const authInfo = await this.securityClient.authinfo(request);
          this.sessionStorageFactory.asScoped(request).clear();
          // TODO: need a default logout page
          const redirectUrl =
            authInfo.sso_logout_url || this.coreSetup.http.basePath.serverBasePath || '/';
          return response.redirected({
            headers: {
              location: redirectUrl,
            },
          });
        } catch (error) {
          context.security_plugin.logger.error(`SAML logout failed: ${error}`);
          return response.badRequest();
        }
      }
    );
  }
}
