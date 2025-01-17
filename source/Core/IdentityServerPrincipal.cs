﻿/*
 * Copyright 2014, 2015 Dominick Baier, Brock Allen
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

using IdentityModel;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;

namespace IdentityServer3.Core
{
    /// <summary>
    /// Helps creating valid identityserver principals (contain the required claims like sub, auth_time, amr, ...)
    /// </summary>
    public static class IdentityServerPrincipal
    {
        /// <summary>
        /// Creates an identityserver principal by specifying the required claims
        /// </summary>
        /// <param name="subject">Subject ID</param>
        /// <param name="displayName">Display name</param>
        /// <param name="authenticationMethod">Authentication method</param>
        /// <param name="idp">IdP name</param>
        /// <param name="authenticationType">Authentication type</param>
        /// <param name="authenticationTime">Authentication time</param>
        /// <returns>ClaimsPrincipal</returns>
        public static ClaimsPrincipal Create(
            string subject,
            string displayName,
            string authenticationMethod = Constants.AuthenticationMethods.Password,
            string idp = Constants.BuiltInIdentityProvider,
            string authenticationType = Constants.PrimaryAuthenticationType,
            long authenticationTime = 0)
        {
            if (String.IsNullOrWhiteSpace(subject)) throw new ArgumentNullException(nameof(subject));
            if (String.IsNullOrWhiteSpace(displayName)) throw new ArgumentNullException(nameof(displayName));
            if (String.IsNullOrWhiteSpace(authenticationMethod)) throw new ArgumentNullException(nameof(authenticationMethod));
            if (String.IsNullOrWhiteSpace(idp)) throw new ArgumentNullException(nameof(idp));
            if (String.IsNullOrWhiteSpace(authenticationType)) throw new ArgumentNullException(nameof(authenticationType));

            if (authenticationTime <= 0) authenticationTime = DateTimeOffset.UtcNow.ToEpochTime();

            var claims = new List<Claim>
            {
                new Claim(Constants.ClaimTypes.Subject, subject),
                new Claim(Constants.ClaimTypes.Name, displayName),
                new Claim(Constants.ClaimTypes.AuthenticationMethod, authenticationMethod),
                new Claim(Constants.ClaimTypes.IdentityProvider, idp),
                new Claim(Constants.ClaimTypes.AuthenticationTime, authenticationTime.ToString(), ClaimValueTypes.Integer)
            };

            var id = new ClaimsIdentity(claims, authenticationType, Constants.ClaimTypes.Name, Constants.ClaimTypes.Role);
            return new ClaimsPrincipal(id);
        }

        /// <summary>
        /// Derives an identityserver principal from another principal
        /// </summary>
        /// <param name="principal">The other principal</param>
        /// <param name="authenticationType">Authentication type</param>
        /// <returns>ClaimsPrincipal</returns>
        public static ClaimsPrincipal CreateFromPrincipal(ClaimsPrincipal principal, string authenticationType)
        {
            // we require the following claims
            var subject = principal.FindFirst(Constants.ClaimTypes.Subject);
            if (subject == null) throw new InvalidOperationException("sub claim is missing");

            var name = principal.FindFirst(Constants.ClaimTypes.Name);
            if (name == null) throw new InvalidOperationException("name claim is missing");

            var authenticationMethod = principal.FindFirst(Constants.ClaimTypes.AuthenticationMethod);
            if (authenticationMethod == null) throw new InvalidOperationException("amr claim is missing");

            var authenticationTime = principal.FindFirst(Constants.ClaimTypes.AuthenticationTime);
            if (authenticationTime == null) throw new InvalidOperationException("auth_time claim is missing");

            var idp = principal.FindFirst(Constants.ClaimTypes.IdentityProvider);
            if (idp == null) throw new InvalidOperationException("idp claim is missing");

            var id = new ClaimsIdentity(principal.Claims, authenticationType, Constants.ClaimTypes.Name, Constants.ClaimTypes.Role);
            return new ClaimsPrincipal(id);
        }

        /// <summary>
        /// Creates a principal from the subject id and additional claims
        /// </summary>
        /// <param name="subjectId">Subject ID</param>
        /// <param name="additionalClaims">Additional claims</param>
        /// <returns>ClaimsPrincipal</returns>
        public static ClaimsPrincipal FromSubjectId(string subjectId, IEnumerable<Claim> additionalClaims = null)
        {
            var claims = new List<Claim>
            {
                new Claim(Constants.ClaimTypes.Subject, subjectId)
            };

            if (additionalClaims != null)
            {
                claims.AddRange(additionalClaims);
            }

            return Principal.Create(Constants.PrimaryAuthenticationType,
                claims.Distinct(new ClaimComparer()).ToArray());
        }

        /// <summary>
        /// Creates a principal from a list of claims
        /// </summary>
        /// <param name="claims">The claims</param>
        /// <param name="allowMissing">Specifies whether required claims must be present</param>
        /// <returns>ClaimsPrincipal</returns>
        public static ClaimsPrincipal FromClaims(IEnumerable<Claim> claims, bool allowMissing = false)
        {
            var sub = claims.FirstOrDefault(c => c.Type == Constants.ClaimTypes.Subject);
            var amr = claims.FirstOrDefault(c => c.Type == Constants.ClaimTypes.AuthenticationMethod);
            var idp = claims.FirstOrDefault(c => c.Type == Constants.ClaimTypes.IdentityProvider);
            var authTime = claims.FirstOrDefault(c => c.Type == Constants.ClaimTypes.AuthenticationTime);

            var id = new ClaimsIdentity(Constants.BuiltInIdentityProvider);

            if (sub != null)
            {
                id.AddClaim(sub);
            }
            else
            {
                if (allowMissing == false)
                {
                    throw new InvalidOperationException("sub claim is missing");
                }
            }

            if (amr != null)
            {
                id.AddClaim(amr);
            }
            else
            {
                if (allowMissing == false)
                {
                    throw new InvalidOperationException("amr claim is missing");
                }
            }

            if (idp != null)
            {
                id.AddClaim(idp);
            }
            else
            {
                if (allowMissing == false)
                {
                    throw new InvalidOperationException("idp claim is missing");
                }
            }

            if (authTime != null)
            {
                id.AddClaim(authTime);
            }
            else
            {
                if (allowMissing == false)
                {
                    throw new InvalidOperationException("auth_time claim is missing");
                }
            }

            return new ClaimsPrincipal(id);
        }
    }
}