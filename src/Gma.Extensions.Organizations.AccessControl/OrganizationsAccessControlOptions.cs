namespace Gma.Extensions.Organizations.AccessControl;

public sealed class OrganizationsAccessControlOptions
{
    public string OwnerScopeSegmentName { get; set; } = "tenant";
    public string SystemActorId { get; set; } = "organizations-membership-sync";
}
