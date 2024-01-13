using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.ConstrainedExecution;
using System.Runtime.InteropServices;
using System.Security.Permissions;

using Microsoft.Win32.SafeHandles;

namespace System.Win32
{
    /// <summary>
    /// 
    /// </summary>
    internal class SafeHandle : SafeHandleZeroOrMinusOneIsInvalid
    {
        public SafeHandle( SafeHandle safeHandle ) : base( false )
        {
            var suc = false;
            safeHandle.DangerousAddRef( ref suc );
            base.SetHandle( safeHandle.DangerousGetHandle() );
        }
        public SafeHandle( IntPtr handle, bool ownsHandle ): base( ownsHandle ) => base.handle = handle;

        [ReliabilityContract(Consistency.WillNotCorruptState, Cer.MayFail), SecurityPermission(SecurityAction.LinkDemand, UnmanagedCode=true)]
        protected override bool ReleaseHandle()
        {
            if ( !WinApi.CloseHandle( base.handle ) ) throw (new Win32Exception( Marshal.GetLastWin32Error() ));
            base.SetHandle( IntPtr.Zero );
            return (true);
        }
    }

    /// <summary>
    /// 
    /// </summary>
    internal sealed class AccessTokenHandle : SafeHandle
    {
        public AccessTokenHandle( Process process, TokenAccessRights tokenAccessRights ) : base( WinApi.OpenProcessToken( process, tokenAccessRights ) ) { }
    }
}
