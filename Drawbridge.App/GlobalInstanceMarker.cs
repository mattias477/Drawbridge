using System.ComponentModel;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace Drawbridge.App;

/// <summary>
/// Holds a non-exclusive, cross-session mutex so the elevated installer can detect
/// tray processes in every signed-in user's session without preventing those users
/// from each running their own control panel.
/// </summary>
internal sealed class GlobalInstanceMarker : IDisposable
{
    private const uint SddlRevision = 1;
    private const uint Synchronize = 0x00100000;
    private const string MarkerSecurity =
        "D:(A;;GA;;;SY)(A;;GA;;;BA)(A;;0x00100000;;;AU)";
    private readonly SafeWaitHandle _handle;

    private GlobalInstanceMarker(SafeWaitHandle handle) => _handle = handle;

    internal static GlobalInstanceMarker Create(string name)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(name);
        if (!OperatingSystem.IsWindows())
        {
            throw new PlatformNotSupportedException("The global installer marker is available only on Windows.");
        }

        if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
                MarkerSecurity,
                SddlRevision,
                out IntPtr descriptor,
                out _))
        {
            throw new Win32Exception(
                Marshal.GetLastWin32Error(),
                "Could not create the cross-session Drawbridge marker security descriptor.");
        }

        try
        {
            var attributes = new SecurityAttributes
            {
                Length = Marshal.SizeOf<SecurityAttributes>(),
                SecurityDescriptor = descriptor,
                InheritHandle = false,
            };
            SafeWaitHandle handle = CreateMutexExW(
                ref attributes,
                name,
                flags: 0,
                desiredAccess: Synchronize);
            if (handle.IsInvalid)
            {
                int error = Marshal.GetLastWin32Error();
                handle.Dispose();
                throw new Win32Exception(error, "Could not establish the cross-session Drawbridge marker.");
            }

            return new GlobalInstanceMarker(handle);
        }
        finally
        {
            _ = LocalFree(descriptor);
        }
    }

    public void Dispose() => _handle.Dispose();

    [StructLayout(LayoutKind.Sequential)]
    private struct SecurityAttributes
    {
        internal int Length;
        internal IntPtr SecurityDescriptor;

        [MarshalAs(UnmanagedType.Bool)]
        internal bool InheritHandle;
    }

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool ConvertStringSecurityDescriptorToSecurityDescriptorW(
        string stringSecurityDescriptor,
        uint stringSdRevision,
        out IntPtr securityDescriptor,
        out uint securityDescriptorSize);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern SafeWaitHandle CreateMutexExW(
        ref SecurityAttributes mutexAttributes,
        string name,
        uint flags,
        uint desiredAccess);

    [DllImport("kernel32.dll")]
    private static extern IntPtr LocalFree(IntPtr memory);
}
