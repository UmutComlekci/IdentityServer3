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

using IdentityServer3.Core.Models;
using IdentityServer3.Core.Services;
using IdentityServer3.Core.ViewModels;
using System;

namespace IdentityServer3.Core.Results
{
    internal class LoginActionResult : HtmlStreamActionResult
    {
        public LoginActionResult(IViewService viewSvc, LoginViewModel model, SignInMessage message)
            : base(async () => await viewSvc.Login(model, message))
        {
            if (viewSvc == null) throw new ArgumentNullException(nameof(viewSvc));
            if (model == null) throw new ArgumentNullException(nameof(model));
            if (message == null) throw new ArgumentNullException(nameof(message));
        }
    }

}
