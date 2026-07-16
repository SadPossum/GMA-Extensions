namespace Gma.Extensions.Organizations.Tenancy;

using Gma.Framework.AccessControl;

public sealed class OrganizationsTenancyOptions
{
    public ISet<AccessSubjectKind> BypassedSubjectKinds { get; } = new HashSet<AccessSubjectKind>
    {
        AccessSubjectKind.AdminActor,
        AccessSubjectKind.Service,
        AccessSubjectKind.System
    };
}
