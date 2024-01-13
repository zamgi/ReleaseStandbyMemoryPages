using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security;

namespace System.Win32
{
    /// <summary>
    /// 
    /// </summary>
    internal static class WinApi
    {
        private const string Kernel32 = "kernel32.dll";

        [return: MarshalAs(UnmanagedType.Bool)] [DllImport(Kernel32, SetLastError=true)] public static extern bool CloseHandle( IntPtr handle );


		private const string NTDLL = "ntdll.dll";
        [DllImport(NTDLL)] public static extern NtStatus NtSetSystemInformation( SYSTEM_INFORMATION_CLASS infoClass, int[] info, uint length );
		[DllImport(NTDLL)] public static extern NtStatus NtSetSystemInformation( SYSTEM_INFORMATION_CLASS infoClass, NtSetSystemInformation_Commands[] commands, uint length );

		[DllImport(NTDLL, EntryPoint="RtlCopyMemory", SetLastError=false)]
        public static extern void CopyMemory( IntPtr dest, IntPtr src, uint count );


		private const string AdvApi32 = "advapi32.dll";

        [return: MarshalAs(UnmanagedType.Bool)]
		[DllImport(AdvApi32, SetLastError=true), SuppressUnmanagedCodeSecurity]
        private static extern bool AdjustTokenPrivileges( IntPtr accessTokenHandle, [MarshalAs(UnmanagedType.Bool)] bool disableAllPrivileges, IntPtr newPriviledges,
            int bufferLength, IntPtr priorPriviledges, out int returnLength );


        [return: MarshalAs(UnmanagedType.Bool)]
        [DllImport(AdvApi32, SetLastError=true), SuppressUnmanagedCodeSecurity]
        public static extern bool OpenProcessToken( IntPtr unsafeHandle, TokenAccessRights desiredAccess, out IntPtr tokenHandle );


        [return: MarshalAs(UnmanagedType.Bool)]
		[DllImport(AdvApi32, CharSet=CharSet.Unicode, SetLastError=true)]
		public static extern bool LookupPrivilegeValue( string systemName, string name, ref Luid luid );

        public static void AdjustTokenPrivileges( AccessTokenHandle accessTokenHandle, bool disableAllPrivileges, TokenPrivilegeArray newState )
        {
            if ( !AdjustTokenPrivileges( accessTokenHandle.DangerousGetHandle(), disableAllPrivileges,
                                            newState.Ptr, newState.CurrentSize,
                                            IntPtr.Zero, out _ /*var resultSize*/ ) )
            {
                throw (new Win32Exception( Marshal.GetLastWin32Error() ));
            }

            var errorCode = Marshal.GetLastWin32Error();
            if ( errorCode != 0 ) throw (new Win32Exception( errorCode ));
        }

        public static SafeHandle OpenProcessToken( Process process, TokenAccessRights requestedRights )
        {
            if ( !OpenProcessToken( process.Handle, requestedRights, out var ptr ) ) throw (new Win32Exception( Marshal.GetLastWin32Error() ));

            return (new SafeHandle( ptr, true ));
        }
    }
}
