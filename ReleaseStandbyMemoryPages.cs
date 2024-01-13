using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace System.Win32
{
    /// <summary>
	/// 
	/// </summary>
    internal sealed class ReleaseStandbyMemoryPages : IDisposable
    {
        private AccessTokenHandle _SelfProcessAccessTokenHandle;
        public ReleaseStandbyMemoryPages()
		{
            _SelfProcessAccessTokenHandle = new AccessTokenHandle( Process.GetCurrentProcess(), TokenAccessRights.AdjustPrivileges | TokenAccessRights.Query );
            _SelfProcessAccessTokenHandle.EnablePrivilege( Privilege.Debug, Privilege.ProfileSingleProcess );
        }
		~ReleaseStandbyMemoryPages() => _SelfProcessAccessTokenHandle?.Dispose();
        public void Dispose()
		{
            _SelfProcessAccessTokenHandle?.Dispose();
            GC.SuppressFinalize( this );
        }

        public void Run()
        {
            var arr = new[] { NtSetSystemInformation_Commands.MemoryPurgeStandbyList };

            var ntStatus = WinApi.NtSetSystemInformation( SYSTEM_INFORMATION_CLASS.SystemMemoryListInformation, arr, (uint) (sizeof(NtSetSystemInformation_Commands) * arr.Length) );
            if ( 0 < ntStatus )
            {
                throw (new Win32Exception( Marshal.GetLastWin32Error(), $"NTStatus: {ntStatus} ({(uint) ntStatus})" ));
            }
        }

		public static void Exec()
		{
			using ( var self = new ReleaseStandbyMemoryPages() )
			{
				self.Run();
			}
        }
    }
} 
