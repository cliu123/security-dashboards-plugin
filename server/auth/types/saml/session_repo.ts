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

export class SessionRepo {
  public static repo: any[] = [];

  constructor() {}

  public static createSession(saml_response: String, saml_reponse_id: String) {
    let session: any = {};
    session["saml_response"] = saml_response;
    session["saml_reponse_id"] = saml_reponse_id
    SessionRepo.repo.push(session);
  }
}
