/*
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
using IdentityServer3.Core.Configuration;
using IdentityServer3.Core.Configuration.Hosting;
using IdentityServer3.Core.Events;
using IdentityServer3.Core.Extensions;
using IdentityServer3.Core.Logging;
using IdentityServer3.Core.Models;
using IdentityServer3.Core.Resources;
using IdentityServer3.Core.Results;
using IdentityServer3.Core.Services;
using IdentityServer3.Core.ViewModels;
using Microsoft.Owin;
using Newtonsoft.Json;
using System;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Security.Claims;
using System.Threading.Tasks;
using System.Web.Http;

namespace IdentityServer3.Core.Endpoints
{
    [ErrorPageFilter]
    [SecurityHeaders]
    [NoCache]
    [PreventUnsupportedRequestMediaTypes(allowFormUrlEncoded: true)]
    [HostAuthentication(Constants.PrimaryAuthenticationType)]
    internal class AuthenticationController : ApiController
    {
        public const int MaxSignInMessageLength = 100;

        private readonly static ILog Logger = LogProvider.GetCurrentClassLogger();

        private readonly IOwinContext _context;
        private readonly IViewService _viewService;
        private readonly IUserService _userService;
        private readonly IdentityServerOptions _options;
        private readonly IClientStore _clientStore;
        private readonly IEventService _eventService;
        private readonly ILocalizationService _localizationService;
        private readonly SessionCookie _sessionCookie;
        private readonly MessageCookie<SignInMessage> _signInMessageCookie;
        private readonly MessageCookie<SignOutMessage> _signOutMessageCookie;
        private readonly LastUserNameCookie _lastUserNameCookie;
        private readonly AntiForgeryToken _antiForgeryToken;

        public AuthenticationController(
            OwinEnvironmentService owin,
            IViewService viewService,
            IUserService userService,
            IdentityServerOptions idSvrOptions,
            IClientStore clientStore,
            IEventService eventService,
            ILocalizationService localizationService,
            SessionCookie sessionCookie,
            MessageCookie<SignInMessage> signInMessageCookie,
            MessageCookie<SignOutMessage> signOutMessageCookie,
            LastUserNameCookie lastUsernameCookie,
            AntiForgeryToken antiForgeryToken)
        {
            _context = new OwinContext(owin.Environment);
            _viewService = viewService;
            _userService = userService;
            _options = idSvrOptions;
            _clientStore = clientStore;
            _eventService = eventService;
            _localizationService = localizationService;
            _sessionCookie = sessionCookie;
            _signInMessageCookie = signInMessageCookie;
            _signOutMessageCookie = signOutMessageCookie;
            _lastUserNameCookie = lastUsernameCookie;
            _antiForgeryToken = antiForgeryToken;
        }

        [Route(Constants.RoutePaths.Login, Name = Constants.RouteNames.Login)]
        [HttpGet]
        public async Task<IHttpActionResult> Login(string signin = null)
        {
            Logger.Info("Login page requested");

            if (signin.IsMissing())
            {
                Logger.Info("No signin id passed");
                return HandleNoSignin();
            }

            if (signin.Length > MaxSignInMessageLength)
            {
                Logger.Error("Signin parameter passed was larger than max length");
                return RenderErrorPage();
            }

            var signInMessage = _signInMessageCookie.Read(signin);
            if (signInMessage == null)
            {
                Logger.Info("No cookie matching signin id found");
                return HandleNoSignin();
            }

            Logger.DebugFormat("signin message passed to login: {0}", JsonConvert.SerializeObject(signInMessage, Formatting.Indented));

            var preAuthContext = new PreAuthenticationContext { SignInMessage = signInMessage };
            await _userService.PreAuthenticateAsync(preAuthContext);

            var authResult = preAuthContext.AuthenticateResult;
            if (authResult != null)
            {
                if (authResult.IsError)
                {
                    Logger.WarnFormat("user service returned an error message: {0}", authResult.ErrorMessage);

                    await _eventService.RaisePreLoginFailureEventAsync(signin, signInMessage, authResult.ErrorMessage);

                    if (preAuthContext.ShowLoginPageOnErrorResult)
                    {
                        Logger.Debug("ShowLoginPageOnErrorResult set to true, showing login page with error");
                        return await RenderLoginPage(signInMessage, signin, authResult.ErrorMessage);
                    }
                    else
                    {
                        Logger.Debug("ShowLoginPageOnErrorResult set to false, showing error page with error");
                        return RenderErrorPage(authResult.ErrorMessage);
                    }
                }

                Logger.Info("user service returned a login result");

                await _eventService.RaisePreLoginSuccessEventAsync(signin, signInMessage, authResult);

                return await SignInAndRedirectAsync(signInMessage, signin, authResult);
            }

            if (signInMessage.IdP.IsPresent())
            {
                Logger.InfoFormat("identity provider requested, redirecting to: {0}", signInMessage.IdP);
                return await LoginExternal(signin, signInMessage.IdP);
            }

            return await RenderLoginPage(signInMessage, signin);
        }

        [Route(Constants.RoutePaths.Login)]
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IHttpActionResult> LoginLocal(string signin, LoginCredentials model)
        {
            Logger.Info("Login page submitted");

            if (_options.AuthenticationOptions.EnableLocalLogin == false)
            {
                Logger.Warn("EnableLocalLogin disabled -- returning 405 MethodNotAllowed");
                return StatusCode(HttpStatusCode.MethodNotAllowed);
            }

            if (signin.IsMissing())
            {
                Logger.Info("No signin id passed");
                return HandleNoSignin();
            }

            if (signin.Length > MaxSignInMessageLength)
            {
                Logger.Error("Signin parameter passed was larger than max length");
                return RenderErrorPage();
            }
            
            var signInMessage = _signInMessageCookie.Read(signin);
            if (signInMessage == null)
            {
                Logger.Info("No cookie matching signin id found");
                return HandleNoSignin();
            }

            if (!(await IsLocalLoginAllowedForClient(signInMessage)))
            {
                Logger.ErrorFormat("Login not allowed for client {0}", signInMessage.ClientId);
                return RenderErrorPage();
            }

            if (model == null)
            {
                Logger.Error("no data submitted");
                return await RenderLoginPage(signInMessage, signin, _localizationService.GetMessage(Messages.InvalidUsernameOrPassword));
            }

            if (String.IsNullOrWhiteSpace(model.Username))
            {
                ModelState.AddModelError("Username", _localizationService.GetMessage(Messages.UsernameRequired));
            }
            
            if (String.IsNullOrWhiteSpace(model.Password))
            {
                ModelState.AddModelError("Password", _localizationService.GetMessage(Messages.PasswordRequired));
            }

            model.RememberMe = _options.AuthenticationOptions.CookieOptions.CalculateRememberMeFromUserInput(model.RememberMe);

            if (!ModelState.IsValid)
            {
                Logger.Warn("validation error: username or password missing");
                return await RenderLoginPage(signInMessage, signin, ModelState.GetError(), model.Username, model.RememberMe == true);
            }

            if (model.Username.Length > _options.InputLengthRestrictions.UserName || model.Password.Length > _options.InputLengthRestrictions.Password)
            {
                Logger.Error("username or password submitted beyond allowed length");
                return await RenderLoginPage(signInMessage, signin);
            }

            var authenticationContext = new LocalAuthenticationContext
            {
                UserName = model.Username.Trim(),
                Password = model.Password.Trim(),
                SignInMessage = signInMessage
            };

            await _userService.AuthenticateLocalAsync(authenticationContext);
            
            var authResult = authenticationContext.AuthenticateResult;
            if (authResult == null)
            {
                Logger.WarnFormat("user service indicated incorrect username or password for username: {0}", model.Username);
                
                var errorMessage = _localizationService.GetMessage(Messages.InvalidUsernameOrPassword);
                await _eventService.RaiseLocalLoginFailureEventAsync(model.Username, signin, signInMessage, errorMessage);
                
                return await RenderLoginPage(signInMessage, signin, errorMessage, model.Username, model.RememberMe == true);
            }

            if (authResult.IsError)
            {
                Logger.WarnFormat("user service returned an error message: {0}", authResult.ErrorMessage);

                await _eventService.RaiseLocalLoginFailureEventAsync(model.Username, signin, signInMessage, authResult.ErrorMessage);
                
                return await RenderLoginPage(signInMessage, signin, authResult.ErrorMessage, model.Username, model.RememberMe == true);
            }

            Logger.Info("Login credentials successfully validated by user service");

            await _eventService.RaiseLocalLoginSuccessEventAsync(model.Username, signin, signInMessage, authResult);

            _lastUserNameCookie.SetValue(model.Username);

            return await SignInAndRedirectAsync(signInMessage, signin, authResult, model.RememberMe);
        }

        [Route(Constants.RoutePaths.LoginExternal, Name = Constants.RouteNames.LoginExternal)]
        [HttpGet]
        public async Task<IHttpActionResult> LoginExternal(string signin, string provider)
        {
            Logger.InfoFormat("External login requested for provider: {0}", provider);

            if (provider.IsMissing())
            {
                Logger.Error("No provider passed");
                return RenderErrorPage(_localizationService.GetMessage(Messages.NoExternalProvider));
            }

            if (provider.Length > _options.InputLengthRestrictions.IdentityProvider)
            {
                Logger.Error("Provider parameter passed was larger than max length");
                return RenderErrorPage();
            }

            if (signin.IsMissing())
            {
                Logger.Info("No signin id passed");
                return HandleNoSignin();
            }

            if (signin.Length > MaxSignInMessageLength)
            {
                Logger.Error("Signin parameter passed was larger than max length");
                return RenderErrorPage();
            }

            var signInMessage = _signInMessageCookie.Read(signin);
            if (signInMessage == null)
            {
                Logger.Info("No cookie matching signin id found");
                return HandleNoSignin();
            }

            if (!(await _clientStore.IsValidIdentityProviderAsync(signInMessage.ClientId, provider)))
            {
                var msg = String.Format("External login error: provider {0} not allowed for client: {1}", provider, signInMessage.ClientId);
                Logger.ErrorFormat(msg);
                await _eventService.RaiseFailureEndpointEventAsync(EventConstants.EndpointNames.Authenticate, msg);
                return RenderErrorPage();
            }
            
            if (_context.IsValidExternalAuthenticationProvider(provider) == false)
            {
                var msg = String.Format("External login error: provider requested {0} is not a configured external provider", provider);
                Logger.ErrorFormat(msg);
                await _eventService.RaiseFailureEndpointEventAsync(EventConstants.EndpointNames.Authenticate, msg);
                return RenderErrorPage();
            }

            var authProp = new Microsoft.Owin.Security.AuthenticationProperties
            {
                RedirectUri = Url.Route(Constants.RouteNames.LoginExternalCallback, null)
            };

            Logger.Info("Triggering challenge for external identity provider");

            // add the id to the dictionary so we can recall the cookie id on the callback
            authProp.Dictionary.Add(Constants.Authentication.SigninId, signin);
            authProp.Dictionary.Add(Constants.Authentication.KatanaAuthenticationType, provider);
            _context.Authentication.Challenge(authProp, provider);
            
            return Unauthorized();
        }

        [Route(Constants.RoutePaths.LoginExternalCallback, Name = Constants.RouteNames.LoginExternalCallback)]
        [HttpGet]
        public async Task<IHttpActionResult> LoginExternalCallback(string error = null)
        {
            Logger.Info("Callback invoked from external identity provider");
            
            if (error.IsPresent())
            {
                if (error.Length > _options.InputLengthRestrictions.ExternalError) error = error.Substring(0, _options.InputLengthRestrictions.ExternalError);

                Logger.ErrorFormat("External identity provider returned error: {0}", error);
                await _eventService.RaiseExternalLoginErrorEventAsync(error);
                return RenderErrorPage(String.Format(_localizationService.GetMessage(Messages.ExternalProviderError), error));
            }

            var signInId = await _context.GetSignInIdFromExternalProvider();
            if (signInId.IsMissing())
            {
                Logger.Info("No signin id passed");
                return HandleNoSignin();
            }

            var signInMessage = _signInMessageCookie.Read(signInId);
            if (signInMessage == null)
            {
                Logger.Info("No cookie matching signin id found");
                return HandleNoSignin();
            }

            var user = await _context.GetIdentityFromExternalProvider();
            if (user == null)
            {
                Logger.Error("no identity from external identity provider");
                return await RenderLoginPage(signInMessage, signInId, _localizationService.GetMessage(Messages.NoMatchingExternalAccount));
            }

            var externalIdentity = ExternalIdentity.FromClaims(user.Claims);
            if (externalIdentity == null)
            {
                var claims = user.Claims.Select(x => new { x.Type, x.Value });
                Logger.ErrorFormat("no subject or unique identifier claims from external identity provider. Claims provided:\r\n{0}", LogSerializer.Serialize(claims));
                return await RenderLoginPage(signInMessage, signInId, _localizationService.GetMessage(Messages.NoMatchingExternalAccount));
            }

            Logger.InfoFormat("external user provider: {0}, provider ID: {1}", externalIdentity.Provider, externalIdentity.ProviderId);

            var externalContext = new ExternalAuthenticationContext
            {
                ExternalIdentity = externalIdentity,
                SignInMessage = signInMessage
            };

            await _userService.AuthenticateExternalAsync(externalContext);
            
            var authResult = externalContext.AuthenticateResult;
            if (authResult == null)
            {
                Logger.Warn("user service failed to authenticate external identity");
                
                var msg = _localizationService.GetMessage(Messages.NoMatchingExternalAccount);
                await _eventService.RaiseExternalLoginFailureEventAsync(externalIdentity, signInId, signInMessage, msg);
                
                return await RenderLoginPage(signInMessage, signInId, msg);
            }

            if (authResult.IsError)
            {
                Logger.WarnFormat("user service returned error message: {0}", authResult.ErrorMessage);

                await _eventService.RaiseExternalLoginFailureEventAsync(externalIdentity, signInId, signInMessage, authResult.ErrorMessage);
                
                return await RenderLoginPage(signInMessage, signInId, authResult.ErrorMessage);
            }

            Logger.Info("External identity successfully validated by user service");

            await _eventService.RaiseExternalLoginSuccessEventAsync(externalIdentity, signInId, signInMessage, authResult);

            return await SignInAndRedirectAsync(signInMessage, signInId, authResult);
        }

        [Route(Constants.RoutePaths.ResumeLoginFromRedirect, Name = Constants.RouteNames.ResumeLoginFromRedirect)]
        [HttpGet]
        public async Task<IHttpActionResult> ResumeLoginFromRedirect(string resume)
        {
            Logger.Info("Callback requested to resume login from partial login");

            if (resume.IsMissing())
            {
                Logger.Error("no resumeId passed");
                return RenderErrorPage();
            }

            if (resume.Length > MaxSignInMessageLength)
            {
                Logger.Error("resumeId length longer than allowed length");
                return RenderErrorPage();
            }

            var user = await _context.GetIdentityFromPartialSignIn();
            if (user == null)
            {
                Logger.Error("no identity from partial login");
                return RenderErrorPage();
            }

            var type = GetClaimTypeForResumeId(resume);
            var resumeClaim = user.FindFirst(type);
            if (resumeClaim == null)
            {
                Logger.Error("no claim matching resumeId");
                return RenderErrorPage();
            }

            var signInId = resumeClaim.Value;
            if (signInId.IsMissing())
            {
                Logger.Error("No signin id found in resume claim");
                return RenderErrorPage();
            }

            var signInMessage = _signInMessageCookie.Read(signInId);
            if (signInMessage == null)
            {
                Logger.Error("No cookie matching signin id found");
                return RenderErrorPage();
            }

            AuthenticateResult result = null;

            // determine which return path the user is taking -- are they coming from
            // a ExternalProvider partial logon, or not
            var externalProviderClaim = user.FindFirst(Constants.ClaimTypes.ExternalProviderUserId);

            // cleanup the claims from the partial login
            if (user.HasClaim(c => c.Type == Constants.ClaimTypes.PartialLoginRestartUrl))
            {
                user.RemoveClaim(user.FindFirst(Constants.ClaimTypes.PartialLoginRestartUrl));
            }
            if (user.HasClaim(c => c.Type == Constants.ClaimTypes.PartialLoginReturnUrl))
            {
                user.RemoveClaim(user.FindFirst(Constants.ClaimTypes.PartialLoginReturnUrl));
            }
            if (user.HasClaim(c => c.Type == Constants.ClaimTypes.ExternalProviderUserId))
            {
                user.RemoveClaim(user.FindFirst(Constants.ClaimTypes.ExternalProviderUserId));
            }
            if (user.HasClaim(c => c.Type == GetClaimTypeForResumeId(resume)))
            {
                user.RemoveClaim(user.FindFirst(GetClaimTypeForResumeId(resume)));
            }

            if (externalProviderClaim != null)
            {
                Logger.Info("using ExternalProviderUserId to call AuthenticateExternalAsync");

                var provider = externalProviderClaim.Issuer;
                var providerId = externalProviderClaim.Value;
                var externalIdentity = new ExternalIdentity
                {
                    Provider = provider,
                    ProviderId = providerId,
                    Claims = user.Claims
                };

                Logger.InfoFormat("external user provider: {0}, provider ID: {1}", externalIdentity.Provider, externalIdentity.ProviderId);

                var externalContext = new ExternalAuthenticationContext
                {
                    ExternalIdentity = externalIdentity,
                    SignInMessage = signInMessage
                };

                await _userService.AuthenticateExternalAsync(externalContext);

                result = externalContext.AuthenticateResult;
                if (result == null)
                {
                    Logger.Warn("user service failed to authenticate external identity");

                    var msg = _localizationService.GetMessage(Messages.NoMatchingExternalAccount);
                    await _eventService.RaiseExternalLoginFailureEventAsync(externalIdentity, signInId, signInMessage, msg);

                    return await RenderLoginPage(signInMessage, signInId, msg);
                }

                if (result.IsError)
                {
                    Logger.WarnFormat("user service returned error message: {0}", result.ErrorMessage);

                    await _eventService.RaiseExternalLoginFailureEventAsync(externalIdentity, signInId, signInMessage, result.ErrorMessage);

                    return await RenderLoginPage(signInMessage, signInId, result.ErrorMessage);
                }

                Logger.Info("External identity successfully validated by user service");

                await _eventService.RaiseExternalLoginSuccessEventAsync(externalIdentity, signInId, signInMessage, result);
            }
            else
            {
                // check to see if the resultant user has all the claim types needed to login
                if (!Constants.AuthenticateResultClaimTypes.All(claimType => user.HasClaim(c => c.Type == claimType)))
                {
                    Logger.Error("Missing AuthenticateResultClaimTypes -- rendering error page");
                    return RenderErrorPage();
                }

                // this is a normal partial login continuation
                Logger.Info("Partial login resume success -- logging user in");

                result = new AuthenticateResult(new ClaimsPrincipal(user));

                await _eventService.RaisePartialLoginCompleteEventAsync(result.User.Identities.First(), signInId, signInMessage);
            }

            // check to see if user clicked "remember me" on login page
            bool? rememberMe = await _context.GetPartialLoginRememberMeAsync();

            return await SignInAndRedirectAsync(signInMessage, signInId, result, rememberMe);
        }

        [Route(Constants.RoutePaths.Logout, Name = Constants.RouteNames.LogoutPrompt)]
        [HttpGet]
        public async Task<IHttpActionResult> LogoutPrompt(string id = null)
        {
            if (id != null && id.Length > MaxSignInMessageLength)
            {
                Logger.Error("Logout prompt requested, but id param is longer than allowed length");
                return RenderErrorPage();
            }

            var user = (ClaimsPrincipal)User;
            if (user == null || user.Identity.IsAuthenticated == false)
            {
                // user is already logged out, so just trigger logout cleanup
                return await Logout(id);
            }

            var sub = user.GetSubjectId();
            Logger.InfoFormat("Logout prompt for subject: {0}", sub);

            if (_options.AuthenticationOptions.RequireSignOutPrompt == false)
            {
                var message = _signOutMessageCookie.Read(id);
                if (message != null && message.ClientId.IsPresent())
                {
                    var client = await _clientStore.FindClientByIdAsync(message.ClientId);
                    if (client != null && client.RequireSignOutPrompt == true)
                    {
                        Logger.InfoFormat("SignOutMessage present (from client {0}) but RequireSignOutPrompt is true, rendering logout prompt", message.ClientId);
                        return RenderLogoutPromptPage(id);
                    }

                    Logger.InfoFormat("SignOutMessage present (from client {0}) and RequireSignOutPrompt is false, performing logout", message.ClientId);
                    return await Logout(id);
                }

                if (!_options.AuthenticationOptions.EnableSignOutPrompt)
                {
                    Logger.InfoFormat("EnableSignOutPrompt set to false, performing logout");
                    return await Logout(id);
                }

                Logger.InfoFormat("EnableSignOutPrompt set to true, rendering logout prompt");
            }
            else
            {
                Logger.InfoFormat("RequireSignOutPrompt set to true, rendering logout prompt");
            }

            return RenderLogoutPromptPage(id);
        }

        [Route(Constants.RoutePaths.Logout, Name = Constants.RouteNames.Logout)]
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IHttpActionResult> Logout(string id = null)
        {
            Logger.Info("Logout endpoint submitted");

            if (id != null && id.Length > MaxSignInMessageLength)
            {
                Logger.Error("id param is longer than allowed length");
                return RenderErrorPage();
            }
            
            var user = (ClaimsPrincipal)User;
            if (user != null && user.Identity.IsAuthenticated)
            {
                var sub = user.GetSubjectId();
                Logger.InfoFormat("Logout requested for subject: {0}", sub);
            }

            Logger.Info("Clearing cookies");
            _context.QueueRemovalOfSignOutMessageCookie(id);
            _context.ClearAuthenticationCookies();
            _context.SignOutOfExternalIdP(id);

            string clientId = null;
            var message = _signOutMessageCookie.Read(id);
            if (message != null)
            {
                clientId = message.ClientId;
            }
            await _context.CallUserServiceSignOutAsync(clientId);

            if (user != null && user.Identity.IsAuthenticated)
            {
                await _eventService.RaiseLogoutEventAsync(user, id, message);
            }

            return await RenderLoggedOutPage(id);
        }

        private IHttpActionResult HandleNoSignin()
        {
            if (_options.AuthenticationOptions.InvalidSignInRedirectUrl.IsMissing())
            {
                return RenderErrorPage(_localizationService.GetMessage(Messages.NoSignInCookie));
            }

            var url = _options.AuthenticationOptions.InvalidSignInRedirectUrl;
            if (url.StartsWith("~/"))
            {
                url = url.Substring(2);
                url = Request.GetOwinEnvironment().GetIdentityServerBaseUrl() + url;
            }
            else if (url.StartsWith("/"))
            {
                url = Request.GetOwinEnvironment().GetIdentityServerHost() + url;
            }
            else
            {
                url = _options.AuthenticationOptions.InvalidSignInRedirectUrl;
            }

            return Redirect(url);
        }
        
        private async Task<IHttpActionResult> SignInAndRedirectAsync(SignInMessage signInMessage, string signInMessageId, AuthenticateResult authResult, bool? rememberMe = null)
        {
            var postAuthenActionResult = await PostAuthenticateAsync(signInMessage, signInMessageId, authResult);
            if (postAuthenActionResult != null)
            {
                if (postAuthenActionResult.Item1 != null)
                {
                    return postAuthenActionResult.Item1;
                }

                if (postAuthenActionResult.Item2 != null)
                {
                    authResult = postAuthenActionResult.Item2;
                }
            }

            // check to see if idp used to signin matches 
            if (signInMessage.IdP.IsPresent() && 
                authResult.IsPartialSignIn == false && 
                authResult.HasSubject && 
                authResult.User.GetIdentityProvider() != signInMessage.IdP)
            {
                // this is an error -- the user service did not set the idp to the one requested
                Logger.ErrorFormat("IdP requested was: {0}, but the user service issued signin for IdP: {1}", signInMessage.IdP, authResult.User.GetIdentityProvider());
                return RenderErrorPage();
            }

            ClearAuthenticationCookiesForNewSignIn(authResult);
            IssueAuthenticationCookie(signInMessageId, authResult, rememberMe);

            var redirectUrl = GetRedirectUrl(signInMessage, authResult);
            Logger.InfoFormat("redirecting to: {0}", redirectUrl);
            return Redirect(redirectUrl);
        }

        private async Task<Tuple<IHttpActionResult, AuthenticateResult>> PostAuthenticateAsync(SignInMessage signInMessage, string signInMessageId, AuthenticateResult result)
        {
            if (result.IsPartialSignIn == false)
            {
                Logger.Info("Calling PostAuthenticateAsync on the user service");

                var ctx = new PostAuthenticationContext
                {
                    SignInMessage = signInMessage,
                    AuthenticateResult = result
                };
                await _userService.PostAuthenticateAsync(ctx);

                var authResult = ctx.AuthenticateResult;
                if (authResult == null)
                {
                    Logger.Error("user service PostAuthenticateAsync returned a null AuthenticateResult");
                    return new Tuple<IHttpActionResult,AuthenticateResult>(RenderErrorPage(), null);
                }

                if (authResult.IsError)
                {
                    Logger.WarnFormat("user service PostAuthenticateAsync returned an error message: {0}", authResult.ErrorMessage);
                    if (ctx.ShowLoginPageOnErrorResult)
                    {
                        Logger.Debug("ShowLoginPageOnErrorResult set to true, showing login page with error");
                        return new Tuple<IHttpActionResult, AuthenticateResult>(await RenderLoginPage(signInMessage, signInMessageId, authResult.ErrorMessage), null);
                    }
                    else
                    {
                        Logger.Debug("ShowLoginPageOnErrorResult set to false, showing error page with error");
                        return new Tuple<IHttpActionResult, AuthenticateResult>(RenderErrorPage(authResult.ErrorMessage), null);
                    }
                }

                if (result != authResult)
                {
                    result = authResult;
                    Logger.Info("user service PostAuthenticateAsync returned a different AuthenticateResult");
                }
            }
            
            return new Tuple<IHttpActionResult, AuthenticateResult>(null, result);
        }


        private void IssueAuthenticationCookie(string signInMessageId, AuthenticateResult authResult, bool? rememberMe = null)
        {
            if (authResult == null) throw new ArgumentNullException(nameof(authResult));

            if (authResult.IsPartialSignIn)
            {
                Logger.Info("issuing partial signin cookie");
            }
            else
            {
                Logger.Info("issuing primary signin cookie");
            }

            var props = new Microsoft.Owin.Security.AuthenticationProperties();

            var id = authResult.User.Identities.First();
            if (authResult.IsPartialSignIn)
            {
                // add claim so partial redirect can return here to continue login
                // we need a random ID to resume, and this will be the query string
                // to match a claim added. the claim added will be the original 
                // signIn ID. 
                var resumeId = CryptoRandom.CreateUniqueId();

                var resumeLoginUrl = _context.GetPartialLoginResumeUrl(resumeId);
                var resumeLoginClaim = new Claim(Constants.ClaimTypes.PartialLoginReturnUrl, resumeLoginUrl);
                id.AddClaim(resumeLoginClaim);
                id.AddClaim(new Claim(GetClaimTypeForResumeId(resumeId), signInMessageId));

                // add url to start login process over again (which re-triggers preauthenticate)
                var restartUrl = _context.GetPartialLoginRestartUrl(signInMessageId);
                id.AddClaim(new Claim(Constants.ClaimTypes.PartialLoginRestartUrl, restartUrl));
            }
            else
            {
                _signInMessageCookie.Clear(signInMessageId);
                _sessionCookie.IssueSessionId(rememberMe);
            }

            if (!authResult.IsPartialSignIn)
            {
                // don't issue persistnt cookie if it's a partial signin
                if (rememberMe == true ||
                    (rememberMe != false && _options.AuthenticationOptions.CookieOptions.IsPersistent))
                {
                    // only issue persistent cookie if user consents (rememberMe == true) or
                    // if server is configured to issue persistent cookies and user has not explicitly
                    // denied the rememberMe (false)
                    // if rememberMe is null, then user was not prompted for rememberMe
                    props.IsPersistent = true;
                    if (rememberMe == true)
                    {
                        var expires = DateTimeHelper.UtcNow.Add(_options.AuthenticationOptions.CookieOptions.RememberMeDuration);
                        props.ExpiresUtc = new DateTimeOffset(expires);
                    }
                }
            }
            else
            {
                if (rememberMe != null)
                {
                    // if rememberme set, then store for later use once we need to issue login cookie
                    props.Dictionary.Add(Constants.Authentication.PartialLoginRememberMe, rememberMe.Value ? "true" : "false");
                }
            }

            _context.Authentication.SignIn(props, id);
        }

        private static string GetClaimTypeForResumeId(string resume)
        {
            return String.Format(Constants.ClaimTypes.PartialLoginResumeId, resume);
        }

        private Uri GetRedirectUrl(SignInMessage signInMessage, AuthenticateResult authResult)
        {
            if (signInMessage == null) throw new ArgumentNullException(nameof(signInMessage));
            if (authResult == null) throw new ArgumentNullException(nameof(authResult));

            if (authResult.IsPartialSignIn)
            {
                var path = authResult.PartialSignInRedirectPath;
                if (path.StartsWith("~/"))
                {
                    path = path.Substring(2);
                    path = Request.GetIdentityServerBaseUrl() + path;
                }
                var host = new Uri(_context.GetIdentityServerHost());
                return new Uri(host, path);
            }
            else
            {
                return new Uri(signInMessage.ReturnUrl);
            }
        }

        private void ClearAuthenticationCookiesForNewSignIn(AuthenticateResult authResult)
        {
            // on a partial sign-in, preserve the existing primary sign-in
            if (!authResult.IsPartialSignIn)
            {
                _context.Authentication.SignOut(Constants.PrimaryAuthenticationType);
            }
            _context.Authentication.SignOut(
                Constants.ExternalAuthenticationType,
                Constants.PartialSignInAuthenticationType);
        }

        async Task<bool> IsLocalLoginAllowedForClient(SignInMessage message)
        {
            if (message != null && message.ClientId.IsPresent())
            {
                var client = await _clientStore.FindClientByIdAsync(message.ClientId);
                if (client != null)
                {
                    return client.EnableLocalLogin;
                }
            }

            return true;
        }

        private async Task<IHttpActionResult> RenderLoginPage(SignInMessage message, string signInMessageId, string errorMessage = null, string username = null, bool rememberMe = false)
        {
            if (message == null) throw new ArgumentNullException(nameof(message));

            username = GetUserNameForLoginPage(message, username);

            var isLocalLoginAllowedForClient = await IsLocalLoginAllowedForClient(message);
            var isLocalLoginAllowed = isLocalLoginAllowedForClient && _options.AuthenticationOptions.EnableLocalLogin;

            var idpRestrictions = await _clientStore.GetIdentityProviderRestrictionsAsync(message.ClientId);
            var providers = _context.GetExternalAuthenticationProviders(idpRestrictions);
            var providerLinks = _context.GetLinksFromProviders(providers, signInMessageId);
            var visibleLinks = providerLinks.FilterHiddenLinks();
            var client = await _clientStore.FindClientByIdAsync(message.ClientId);

            if (errorMessage != null)
            {
                Logger.InfoFormat("rendering login page with error message: {0}", errorMessage);
            }
            else
            {
                if (isLocalLoginAllowed == false)
                {
                    if (_options.AuthenticationOptions.EnableLocalLogin)
                    {
                        Logger.Info("local login disabled");
                    }
                    if (isLocalLoginAllowedForClient)
                    {
                        Logger.Info("local login disabled for the client");
                    }

                    string url = null;

                    if (!providerLinks.Any())
                    {
                        Logger.Info("no providers registered for client");
                        return RenderErrorPage();
                    }
                    else if (providerLinks.Count() == 1)
                    {
                        Logger.Info("only one provider for client");
                        url = providerLinks.First().Href;
                    }
                    else if (visibleLinks.Count() == 1)
                    {
                        Logger.Info("only one visible provider");
                        url = visibleLinks.First().Href;
                    }

                    if (url.IsPresent())
                    {
                        Logger.InfoFormat("redirecting to provider URL: {0}", url);
                        return Redirect(url);
                    }
                }

                Logger.Info("rendering login page");
            }

            var loginPageLinks = _options.AuthenticationOptions.LoginPageLinks.Render(Request.GetIdentityServerBaseUrl(), signInMessageId);

            var loginModel = new LoginViewModel
            {
                RequestId = _context.GetRequestId(),
                SiteName = _options.SiteName,
                SiteUrl = Request.GetIdentityServerBaseUrl(),
                ExternalProviders = visibleLinks,
                AdditionalLinks = loginPageLinks,
                ErrorMessage = errorMessage,
                LoginUrl = isLocalLoginAllowed ? Url.Route(Constants.RouteNames.Login, new { signin = signInMessageId }) : null,
                AllowRememberMe = _options.AuthenticationOptions.CookieOptions.AllowRememberMe,
                RememberMe = _options.AuthenticationOptions.CookieOptions.AllowRememberMe && rememberMe,
                CurrentUser = _context.GetCurrentUserDisplayName(),
                LogoutUrl = _context.GetIdentityServerLogoutUrl(),
                AntiForgery = _antiForgeryToken.GetAntiForgeryToken(),
                Username = username,
                ClientName = client?.ClientName,
                ClientUrl = client?.ClientUri,
                ClientLogoUrl = client?.LogoUri
            };

            return new LoginActionResult(_viewService, loginModel, message);
        }

        private string GetUserNameForLoginPage(SignInMessage message, string username)
        {
            if (username.IsMissing() && message.LoginHint.IsPresent())
            {
                if (_options.AuthenticationOptions.EnableLoginHint)
                {
                    Logger.InfoFormat("Using LoginHint for username: {0}", message.LoginHint);
                    username = message.LoginHint;
                }
                else
                {
                    Logger.Warn("Not using LoginHint because EnableLoginHint is false");
                }
            }

            var lastUsernameCookieValue = _lastUserNameCookie.GetValue();
            if (username.IsMissing() && lastUsernameCookieValue.IsPresent())
            {
                Logger.InfoFormat("Using LastUserNameCookie value for username: {0}", lastUsernameCookieValue);
                username = lastUsernameCookieValue;
            }
            return username;
        }

        private IHttpActionResult RenderLogoutPromptPage(string id)
        {
            var logout_url = _context.GetIdentityServerLogoutUrl();
            if (id.IsPresent())
            {
                logout_url += "?id=" + id;
            }

            var logoutModel = new LogoutViewModel
            {
                SiteName = _options.SiteName,
                SiteUrl = _context.GetIdentityServerBaseUrl(),
                CurrentUser = _context.GetCurrentUserDisplayName(),
                LogoutUrl = logout_url,
                AntiForgery = _antiForgeryToken.GetAntiForgeryToken(),
            };

            var message = _signOutMessageCookie.Read(id);
            return new LogoutActionResult(_viewService, logoutModel, message);
        }

        private async Task<IHttpActionResult> RenderLoggedOutPage(string id)
        {
            Logger.Info("rendering logged out page");

            var baseUrl = _context.GetIdentityServerBaseUrl();
            var iframeUrls = _options.RenderProtocolUrls(baseUrl, _sessionCookie.GetSessionId());

            var message = _signOutMessageCookie.Read(id);
            var redirectUrl = message?.ReturnUrl;
            var clientName = await _clientStore.GetClientName(message);
            
            var loggedOutModel = new LoggedOutViewModel
            {
                SiteName = _options.SiteName,
                SiteUrl = baseUrl,
                IFrameUrls = iframeUrls,
                ClientName = clientName,
                RedirectUrl = redirectUrl,
                AutoRedirect = _options.AuthenticationOptions.EnablePostSignOutAutoRedirect,
                AutoRedirectDelay = _options.AuthenticationOptions.PostSignOutAutoRedirectDelay
            };
            return new LoggedOutActionResult(_viewService, loggedOutModel, message);
        }

        private IHttpActionResult RenderErrorPage(string message = null)
        {
            message = message ?? _localizationService.GetMessage(Messages.UnexpectedError);
            var errorModel = new ErrorViewModel
            {
                RequestId = _context.GetRequestId(),
                SiteName = _options.SiteName,
                SiteUrl = _context.GetIdentityServerBaseUrl(),
                ErrorMessage = message,
                CurrentUser = _context.GetCurrentUserDisplayName(),
                LogoutUrl = _context.GetIdentityServerLogoutUrl(),
            };
            var errorResult = new ErrorActionResult(_viewService, errorModel);
            return errorResult;
        }
    }
}