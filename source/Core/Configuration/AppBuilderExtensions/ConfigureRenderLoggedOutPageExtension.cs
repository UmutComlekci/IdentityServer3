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

using IdentityServer3.Core.Extensions;
using System;

namespace Owin
{
    internal static class ConfigureRenderLoggedOutPageExtension
    {
        public static IAppBuilder ConfigureRenderLoggedOutPage(this IAppBuilder app)
        {
            if (app == null) throw new ArgumentNullException(nameof(app));

            return app.Use(async (ctx, next) =>
            {
                await next();

                if (ctx.ShouldRenderLoggedOutPage())
                {
                    // if we're being asked to render the logged out page, then 
                    // change the owin context to look like that request
                    ctx.PrepareContextForLoggedOutPage();

                    // re-trigger pipeline to process logged out page
                    await next();
                }
            });
        }
    }
}