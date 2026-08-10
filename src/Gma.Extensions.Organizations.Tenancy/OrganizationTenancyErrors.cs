namespace Gma.Extensions.Organizations.Tenancy;

public static class OrganizationTenancyErrors
{
    public const string UnauthenticatedCode = "OrganizationsTenancy.Unauthenticated";
    public const string AccessDeniedCode = "OrganizationsTenancy.AccessDenied";
    public const string AccessUnavailableCode = "OrganizationsTenancy.AccessUnavailable";

    public const string UnauthenticatedMessage = "An authenticated subject is required.";
    public const string AccessDeniedMessage = "The authenticated subject cannot access the selected organization.";
    public const string AccessUnavailableMessage = "Organization access could not be verified. Try again later.";
}
