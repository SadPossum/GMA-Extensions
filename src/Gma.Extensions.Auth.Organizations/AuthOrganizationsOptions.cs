namespace Gma.Extensions.Auth.Organizations;

using Gma.Modules.Auth.Contracts;

public sealed class AuthOrganizationsOptions
{
    public string GlobalAuthScopeId { get; set; } = AuthProfile.DefaultGlobalScopeId;
}
