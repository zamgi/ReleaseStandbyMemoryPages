using System.Collections.Generic;
using System.ComponentModel;
using System.Runtime.InteropServices;

namespace System.Win32
{
    /// <summary>
    /// 
    /// </summary>
    internal static class PrivilegesHelper
    {
        private static readonly SortedList< Privilege, Luid      > _LuidList;
        private static readonly SortedList< string   , Privilege > _PrivilegeConstants;

        static PrivilegesHelper()
        {
            _LuidList           = new SortedList< Privilege, Luid >( (int) Privilege._MaxInvalid );
            _PrivilegeConstants = new SortedList< string, Privilege >( (int) Privilege._MaxInvalid, StringComparer.InvariantCulture )
            {
                { "SeAssignPrimaryTokenPrivilege", Privilege.AssignPrimaryToken },
                { "SeAuditPrivilege", Privilege.Audit },
                { "SeBackupPrivilege", Privilege.Backup },
                { "SeChangeNotifyPrivilege", Privilege.ChangeNotify },
                { "SeCreateGlobalPrivilege", Privilege.CreateGlobal },
                { "SeCreatePagefilePrivilege", Privilege.CreatePageFile },
                { "SeCreatePermanentPrivilege", Privilege.CreatePermanent },
                { "SeCreateSymbolicLinkPrivilege", Privilege.CreateSymbolicLink },
                { "SeCreateTokenPrivilege", Privilege.CreateToken },
                { "SeDebugPrivilege", Privilege.Debug },
                { "SeEnableDelegationPrivilege", Privilege.EnableDelegation },
                { "SeImpersonatePrivilege", Privilege.Impersonate },
                { "SeIncreaseBasePriorityPrivilege", Privilege.IncreaseBasePriority },
                { "SeIncreaseQuotaPrivilege", Privilege.IncreaseQuota },
                { "SeIncreaseWorkingSetPrivilege", Privilege.IncreaseWorkingSet },
                { "SeLoadDriverPrivilege", Privilege.LoadDriver },
                { "SeLockMemoryPrivilege", Privilege.LockMemory },
                { "SeMachineAccountPrivilege", Privilege.MachineAccount },
                { "SeManageVolumePrivilege", Privilege.ManageVolume },
                { "SeProfileSingleProcessPrivilege", Privilege.ProfileSingleProcess },
                { "SeRelabelPrivilege", Privilege.Relabel },
                { "SeRemoteShutdownPrivilege", Privilege.RemoteShutdown },
                { "SeRestorePrivilege", Privilege.Restore },
                { "SeSecurityPrivilege", Privilege.Security },
                { "SeShutdownPrivilege", Privilege.Shutdown },
                { "SeSyncAgentPrivilege", Privilege.SyncAgent },
                { "SeSystemEnvironmentPrivilege", Privilege.SystemEnvironment },
                { "SeSystemProfilePrivilege", Privilege.SystemProfile },
                { "SeSystemtimePrivilege", Privilege.SystemTime },
                { "SeTakeOwnershipPrivilege", Privilege.TakeOwnership },
                { "SeTimeZonePrivilege", Privilege.TimeZone },
                { "SeTcbPrivilege", Privilege.TrustedComputerBase },
                { "SeTrustedCredManAccessPrivilege", Privilege.TrustedCredentialManagerAccess },
                { "SeUndockPrivilege", Privilege.Undock },
                { "SeUnsolicitedInputPrivilege", Privilege.UnsolicitedInput }
            };
        }

        private static void AdjustPrivilege( this AccessTokenHandle accessTokenHandle, PrivilegeAttributes privilegeAttributes, Luid[] luid )
        {
            var array = new TokenPrivilegeArray( luid.Length );

            for ( int i = 0; i < luid.Length; i++ )
            {
                var v = new LuidAndAttributes()
                {
                    Attributes = privilegeAttributes,
                    Luid = luid[ i ],
                };
                array[ i ] = v;
            }

            WinApi.AdjustTokenPrivileges( accessTokenHandle, false, array );
        }
        private static void AdjustPrivilege( this AccessTokenHandle accessTokenHandle, PrivilegeAttributes privilegeAttributes, Privilege[] privilege ) => accessTokenHandle.AdjustPrivilege( privilegeAttributes, privilege.GetLuid() );
        public static void EnablePrivilege( this AccessTokenHandle accessTokenHandle, params Privilege[] privilege ) => accessTokenHandle.AdjustPrivilege( PrivilegeAttributes.Enabled, privilege );

        private static Luid[] GetLuid( this Privilege[] privilege )
        {
            var result = new Luid[ privilege.Length ];

            for ( int i = 0; i < privilege.Length; i++ )
            {
                if ( _LuidList.TryGetValue( privilege[ i ], out var luid ) )
                {
                    result[ i ] = luid;
                }
                else
                {
                    luid = new Luid();
                    var pos = _PrivilegeConstants.IndexOfValue( privilege[ i ] );

                    if ( !WinApi.LookupPrivilegeValue( string.Empty, _PrivilegeConstants.Keys[ pos ], ref luid ) )
                    {
                        throw (new Win32Exception( Marshal.GetLastWin32Error() ));
                    }

                    _LuidList.Add( privilege[ i ], luid );
                    result[ i ] = luid;
                }
            }
            return (result);
        }
    }
}

