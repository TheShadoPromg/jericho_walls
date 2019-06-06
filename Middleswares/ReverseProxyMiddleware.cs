using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json;
using rde.edu.do_jericho_walls.Helpers;
using rde.edu.do_jericho_walls.Interfaces;
using rde.edu.do_jericho_walls.Repositories;
using System;
using System.Linq;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;

namespace rde.edu.do_jericho_walls.Middleswares
{
    public class ReverseProxyMiddleware
    {
        private static readonly HttpClient _httpClient = new HttpClient();
        private readonly RequestDelegate _nextMiddleware;

        public ReverseProxyMiddleware(RequestDelegate nextMiddleware)
        {
            _nextMiddleware = nextMiddleware;
        }

        public async Task Invoke(HttpContext context, 
                                 IReverseProxyRepository repository,
                                 IAuthenticationRepository authenticationRepository, 
                                 IConfiguration config,
                                 ILogger<ReverseProxyMiddleware> logger)
        {
            var serviceName = context.Request.Headers["sigirde-service"];

            try
            {
                var service = await repository.GetByName(serviceName);

                if (service == null)
                {
                    logger.LogInformation($"Service {serviceName} not found.");
                    context.Response.StatusCode = 404;
                    return;
                }

                if (!service.Active)
                {
                    logger.LogInformation($"Service {service.Name} is not active.");
                    context.Response.StatusCode = 503;
                    return;
                }

                var authorization = await AuthenticationHelper.AuthorizeForProxy(
                     context.Request.Headers["Authorization"],
                     authenticationRepository,
                     logger,
                     config.GetValue<string>("JWTIssuer"),
                     service.Name
                 );

                if (authorization == null)
                {
                    logger.LogInformation($"Authorization {context.Request.Headers["Authorization"]} is null.");
                    context.Response.StatusCode = 401;
                    return;
                }

                if (authorization.Forbiden)
                {
                    context.Response.StatusCode = 403;
                    return;
                }

                logger.LogInformation($"Reverse proxy to: http://{service.Host}:{service.Port}{context.Request.Path}");
                var targetUri = new Uri($"http://{service.Host}:{service.Port}{context.Request.Path}");

                if (targetUri != null)
                {
                    var j = JsonConvert.SerializeObject(authorization.User);

                    var targetRequestMessage = CreateTargetMessage(context, targetUri);
                    targetRequestMessage.Headers.Add("SIGIRDE-User", Convert.ToBase64String(Encoding.UTF8.GetBytes(j)));

                    using var responseMessage = await _httpClient.SendAsync(targetRequestMessage, HttpCompletionOption.ResponseHeadersRead, context.RequestAborted);
                    context.Response.StatusCode = (int)responseMessage.StatusCode;
                    CopyFromTargetResponseHeaders(context, responseMessage);
                    await responseMessage.Content.CopyToAsync(context.Response.Body);
                    return;
                }

                await _nextMiddleware(context);
            }
            catch (Exception e)
            {
                logger.LogError("Reverse proxy exception Message {@Message} StackTrace {@Stacktrace}.", e.Message, e.StackTrace);
                context.Response.StatusCode = 500;
            }
        }

        private HttpRequestMessage CreateTargetMessage(HttpContext context, Uri targetUri)
        {
            var requestMessage = new HttpRequestMessage();
            CopyFromOriginalRequestContentAndHeaders(context, requestMessage);

            requestMessage.RequestUri = targetUri;
            requestMessage.Headers.Host = targetUri.Host;
            requestMessage.Method = GetMethod(context.Request.Method);

            return requestMessage;
        }

        private void CopyFromOriginalRequestContentAndHeaders(HttpContext context, HttpRequestMessage requestMessage)
        {
            var requestMethod = context.Request.Method;

            if (!HttpMethods.IsGet(requestMethod) &&
              !HttpMethods.IsHead(requestMethod) &&
              !HttpMethods.IsDelete(requestMethod) &&
              !HttpMethods.IsTrace(requestMethod))
            {
                var streamContent = new StreamContent(context.Request.Body);
                requestMessage.Content = streamContent;
            }

            foreach (var header in context.Request.Headers)
            {
                requestMessage.Content?.Headers.TryAddWithoutValidation(header.Key, header.Value.ToArray());
            }
        }

        private void CopyFromTargetResponseHeaders(HttpContext context, HttpResponseMessage responseMessage)
        {
            foreach (var header in responseMessage.Headers)
            {
                context.Response.Headers[header.Key] = header.Value.ToArray();
            }

            foreach (var header in responseMessage.Content.Headers)
            {
                context.Response.Headers[header.Key] = header.Value.ToArray();
            }
            context.Response.Headers.Remove("transfer-encoding");
        }

        private static HttpMethod GetMethod(string method)
        {
            if (HttpMethods.IsDelete(method)) return HttpMethod.Delete;
            if (HttpMethods.IsGet(method)) return HttpMethod.Get;
            if (HttpMethods.IsHead(method)) return HttpMethod.Head;
            if (HttpMethods.IsOptions(method)) return HttpMethod.Options;
            if (HttpMethods.IsPost(method)) return HttpMethod.Post;
            if (HttpMethods.IsPut(method)) return HttpMethod.Put;
            if (HttpMethods.IsTrace(method)) return HttpMethod.Trace;
            return new HttpMethod(method);
        }
    }
}
