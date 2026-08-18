using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace Drawbridge.Core;

/// <summary>Resolves and protects Drawbridge's machine-wide persistent storage.</summary>
public sealed class DrawbridgePaths
{
    private const string ProductDirectoryName = "Drawbridge";
    private const string LocalSystemSid = "S-1-5-18";
    private const string AdministratorsSid = "S-1-5-32-544";
    private const string UsersSid = "S-1-5-32-545";
    private const uint MaximumAllowed = 0x02000000;
    private const uint FileShareRead = 0x00000001;
    private const uint OpenExisting = 3;
    private const uint FileAttributeDirectory = 0x00000010;
    private const uint FileAttributeReparsePoint = 0x00000400;
    private const uint InvalidFileAttributes = 0xFFFFFFFF;
    private const uint FileFlagOpenReparsePoint = 0x00200000;
    private const uint FileFlagBackupSemantics = 0x02000000;
    private const uint TokenAdjustPrivileges = 0x0020;
    private const uint TokenQuery = 0x0008;
    private const uint SePrivilegeEnabled = 0x00000002;
    private const int ErrorFileNotFound = 2;
    private const int ErrorPathNotFound = 3;
    private const int ErrorInsufficientBuffer = 122;
    private const int ErrorNotAllAssigned = 1300;
    private const uint OwnerSecurityInformation = 0x00000001;
    private const uint DaclSecurityInformation = 0x00000004;
    private const uint UnprotectedDaclSecurityInformation = 0x20000000;
    private const uint ProtectedDaclSecurityInformation = 0x80000000;

    private readonly bool _secureAcl;
    private readonly string _ownerSid;
    private readonly string _administratorsSid;
    private readonly string _readersSid;
    private readonly object _aclLock = new();
    private bool _aclApplied;

    public DrawbridgePaths()
        : this(Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            ProductDirectoryName), secureAcl: true)
    {
    }

    public DrawbridgePaths(string rootDirectory, bool secureAcl = false)
        : this(
            rootDirectory,
            secureAcl,
            LocalSystemSid,
            AdministratorsSid,
            UsersSid)
    {
    }

    internal DrawbridgePaths(
        string rootDirectory,
        bool secureAcl,
        string ownerSid,
        string administratorsSid,
        string readersSid)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(rootDirectory);
        ArgumentException.ThrowIfNullOrWhiteSpace(ownerSid);
        ArgumentException.ThrowIfNullOrWhiteSpace(administratorsSid);
        ArgumentException.ThrowIfNullOrWhiteSpace(readersSid);
        RootDirectory = Path.GetFullPath(rootDirectory);
        _secureAcl = secureAcl;
        _ownerSid = ownerSid;
        _administratorsSid = administratorsSid;
        _readersSid = readersSid;
    }

    public string RootDirectory { get; }
    public string SettingsFile => Path.Combine(RootDirectory, "settings.json");
    public string CacheDirectory => Path.Combine(RootDirectory, "cache");
    public string CacheMetadataFile => Path.Combine(CacheDirectory, "metadata.json");
    public string PinFile => Path.Combine(RootDirectory, "pin.json");
    public string LogsDirectory => Path.Combine(RootDirectory, "logs");
    public string ServiceConfigFile => Path.Combine(RootDirectory, "service-config.json");
    public string WebMonitorEnabledFile => Path.Combine(RootDirectory, "webmonitor.enabled");

    /// <summary>Whether this process repaired persisted state that violated the production ACL.</summary>
    public bool SecurityRepairPerformed { get; private set; }

    /// <summary>Whether a pre-existing protected empty DACL from the 2.0 regression was repaired.</summary>
    public bool LegacyEmptyDaclRepairPerformed { get; private set; }

    /// <summary>Whether the data root had no entries before this instance created its standard directories.</summary>
    public bool WasEmptyBeforeEnsureCreated { get; private set; }

    public void EnsureCreated(Action<string>? log = null)
    {
        if (!_secureAcl || !OperatingSystem.IsWindows())
        {
            WasEmptyBeforeEnsureCreated = !Directory.Exists(RootDirectory) ||
                                          !Directory.EnumerateFileSystemEntries(RootDirectory).Any();
            Directory.CreateDirectory(RootDirectory);
            Directory.CreateDirectory(CacheDirectory);
            Directory.CreateDirectory(LogsDirectory);
            return;
        }

        lock (_aclLock)
        {
            if (_aclApplied)
            {
                return;
            }

            ApplyRestrictedAcl(log);
            _aclApplied = true;
        }
    }

    internal void ProtectSensitiveFile(string path)
    {
        if (!_secureAcl || !OperatingSystem.IsWindows())
        {
            return;
        }

        string fullPath = ValidateContainedPath(path);
        using PrivilegeScope? privileges = EnableRepairPrivilegesIfRequired();
        using SafeFileHandle handle = OpenNoFollow(fullPath, expectedDirectory: false);
        ApplyExactSecurity(
            handle,
            isDirectory: false,
            isSensitive: true,
            protectDacl: true,
            inheritToChildren: false);
        VerifyExactSecurity(
            handle,
            isDirectory: false,
            isSensitive: true,
            protectedDacl: true,
            inheritToChildren: false);
    }

    [SupportedOSPlatform("windows")]
    private void ApplyRestrictedAcl(Action<string>? log)
    {
        try
        {
            bool rootExisted = EntryExistsNoFollow(RootDirectory);
            if (rootExisted)
            {
                RejectRootReparsePoint();
            }

            Directory.CreateDirectory(RootDirectory);
            using PrivilegeScope? privileges = EnableRepairPrivilegesIfRequired();
            using SafeFileHandle rootHandle = OpenNoFollow(
                RootDirectory,
                expectedDirectory: true);
            RawSecurityDescriptor existingRootDescriptor = ReadSecurityDescriptor(rootHandle);
            if (rootExisted && IsProtectedEmptyDacl(existingRootDescriptor))
            {
                LegacyEmptyDaclRepairPerformed = true;
            }

            if (rootExisted && !DescriptorMatches(
                    existingRootDescriptor,
                    isDirectory: true,
                    isSensitive: false,
                    protectedDacl: true,
                    inheritToChildren: true))
            {
                SecurityRepairPerformed = true;
            }

            // Every repair handle is opened with MAXIMUM_ALLOWED, which suppresses
            // SetSecurityInfo's automatic child propagation, and without share-write/delete,
            // which makes an outstanding writer a fail-closed startup error.
            ApplyExactSecurity(
                rootHandle,
                isDirectory: true,
                isSensitive: false,
                protectDacl: true,
                inheritToChildren: false);
            VerifyExactSecurity(
                rootHandle,
                isDirectory: true,
                isSensitive: false,
                protectedDacl: true,
                inheritToChildren: false);

            WasEmptyBeforeEnsureCreated = !rootExisted ||
                                          !Directory.EnumerateFileSystemEntries(RootDirectory).Any();
            var createdThisPass = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            bool cacheExisted = EntryExistsNoFollow(CacheDirectory);
            bool logsExisted = EntryExistsNoFollow(LogsDirectory);
            Directory.CreateDirectory(CacheDirectory);
            Directory.CreateDirectory(LogsDirectory);
            if (!cacheExisted)
            {
                createdThisPass.Add(Path.GetFullPath(CacheDirectory));
            }

            if (!logsExisted)
            {
                createdThisPass.Add(Path.GetFullPath(LogsDirectory));
            }

            RepairDirectory(RootDirectory, createdThisPass);

            ApplyExactSecurity(
                rootHandle,
                isDirectory: true,
                isSensitive: false,
                protectDacl: true,
                inheritToChildren: true);
            VerifyExactSecurity(
                rootHandle,
                isDirectory: true,
                isSensitive: false,
                protectedDacl: true,
                inheritToChildren: true);
        }
        catch (Exception ex)
        {
            log?.Invoke($"Could not protect the data directory ACL: {ex.Message}");
            throw;
        }
    }

    [SupportedOSPlatform("windows")]
    private void RepairDirectory(string directoryPath, IReadOnlySet<string> createdThisPass)
    {
        FileSystemInfo[] entries = new DirectoryInfo(directoryPath)
            .EnumerateFileSystemInfos()
            .ToArray();

        // Never expose a damaged PIN—or a crash-leftover atomic PIN temporary file—through
        // the Users-readable parent while repairing it.
        FileSystemInfo[] sensitiveEntries = entries.Where(IsSensitiveEntry).ToArray();
        foreach (FileSystemInfo sensitiveEntry in sensitiveEntries)
        {
            RepairEntry(sensitiveEntry, isSensitive: true, createdThisPass);
        }

        foreach (FileSystemInfo entry in entries)
        {
            if (!sensitiveEntries.Contains(entry, ReferenceEqualityComparer.Instance))
            {
                RepairEntry(entry, isSensitive: false, createdThisPass);
            }
        }
    }

    private bool IsSensitiveEntry(FileSystemInfo entry)
    {
        string fullPath = Path.GetFullPath(entry.FullName);
        if (string.Equals(fullPath, PinFile, StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        return string.Equals(
                   Path.GetDirectoryName(fullPath),
                   RootDirectory,
                   StringComparison.OrdinalIgnoreCase) &&
               entry.Name.StartsWith(".pin.json.", StringComparison.OrdinalIgnoreCase) &&
               entry.Name.EndsWith(".tmp", StringComparison.OrdinalIgnoreCase);
    }

    [SupportedOSPlatform("windows")]
    private void RepairEntry(
        FileSystemInfo entry,
        bool isSensitive,
        IReadOnlySet<string> createdThisPass)
    {
        string fullPath = ValidateContainedPath(entry.FullName);
        bool expectedDirectory = entry is DirectoryInfo;
        bool expectedProtection = isSensitive;
        using SafeFileHandle handle = OpenNoFollow(fullPath, expectedDirectory);
        if (isSensitive && expectedDirectory)
        {
            throw new InvalidOperationException($"The PIN state path is unexpectedly a directory: {fullPath}");
        }

        RawSecurityDescriptor existingDescriptor = ReadSecurityDescriptor(handle);
        bool existedBeforeRepair = !createdThisPass.Contains(fullPath);
        if (existedBeforeRepair && IsProtectedEmptyDacl(existingDescriptor))
        {
            LegacyEmptyDaclRepairPerformed = true;
        }

        if (existedBeforeRepair && !DescriptorMatches(
                existingDescriptor,
                expectedDirectory,
                isSensitive,
                expectedProtection,
                inheritToChildren: expectedDirectory))
        {
            SecurityRepairPerformed = true;
        }

        ApplyExactSecurity(
            handle,
            expectedDirectory,
            isSensitive,
            expectedProtection,
            inheritToChildren: false);
        VerifyExactSecurity(
            handle,
            expectedDirectory,
            isSensitive,
            expectedProtection,
            inheritToChildren: false);

        if (expectedDirectory)
        {
            // This identity-locked directory stays open while its descendants are processed.
            RepairDirectory(fullPath, createdThisPass);
            ApplyExactSecurity(
                handle,
                isDirectory: true,
                isSensitive: false,
                protectDacl: false,
                inheritToChildren: true);
            VerifyExactSecurity(
                handle,
                isDirectory: true,
                isSensitive: false,
                protectedDacl: false,
                inheritToChildren: true);
        }
    }

    [SupportedOSPlatform("windows")]
    private void ApplyExactSecurity(
        SafeFileHandle handle,
        bool isDirectory,
        bool isSensitive,
        bool protectDacl,
        bool inheritToChildren)
    {
        RawSecurityDescriptor descriptor = CreateSecurityDescriptor(
            isDirectory,
            isSensitive,
            protectDacl,
            inheritToChildren);
        SecurityIdentifier descriptorOwner = descriptor.Owner
            ?? throw new InvalidOperationException("The generated ACL has no owner.");
        RawAcl descriptorDacl = descriptor.DiscretionaryAcl
            ?? throw new InvalidOperationException("The generated ACL has no DACL.");
        byte[] ownerBytes = new byte[descriptorOwner.BinaryLength];
        descriptorOwner.GetBinaryForm(ownerBytes, 0);
        byte[] daclBytes = new byte[descriptorDacl.BinaryLength];
        descriptorDacl.GetBinaryForm(daclBytes, 0);
        bool replaceOwner = !string.Equals(
            ReadSecurityDescriptor(handle).Owner?.Value,
            _ownerSid,
            StringComparison.OrdinalIgnoreCase);

        IntPtr ownerPointer = Marshal.AllocHGlobal(ownerBytes.Length);
        IntPtr daclPointer = Marshal.AllocHGlobal(daclBytes.Length);
        try
        {
            Marshal.Copy(ownerBytes, 0, ownerPointer, ownerBytes.Length);
            Marshal.Copy(daclBytes, 0, daclPointer, daclBytes.Length);
            uint information = (replaceOwner ? OwnerSecurityInformation : 0) |
                               DaclSecurityInformation |
                               (protectDacl
                                   ? ProtectedDaclSecurityInformation
                                   : UnprotectedDaclSecurityInformation);
            uint result = SetSecurityInfo(
                handle,
                SeObjectType.FileObject,
                information,
                replaceOwner ? ownerPointer : IntPtr.Zero,
                IntPtr.Zero,
                daclPointer,
                IntPtr.Zero);
            if (result != 0)
            {
                throw new Win32Exception((int)result, "Could not apply the protected data ACL.");
            }
        }
        finally
        {
            Marshal.FreeHGlobal(daclPointer);
            Marshal.FreeHGlobal(ownerPointer);
        }
    }

    [SupportedOSPlatform("windows")]
    private void VerifyExactSecurity(
        SafeFileHandle handle,
        bool isDirectory,
        bool isSensitive,
        bool protectedDacl,
        bool inheritToChildren)
    {
        if (!DescriptorMatches(
                ReadSecurityDescriptor(handle),
                isDirectory,
                isSensitive,
                protectedDacl,
                inheritToChildren))
        {
            throw new InvalidOperationException("The persisted data ACL did not match the required policy after repair.");
        }
    }

    [SupportedOSPlatform("windows")]
    private bool DescriptorMatches(
        RawSecurityDescriptor descriptor,
        bool isDirectory,
        bool isSensitive,
        bool protectedDacl,
        bool inheritToChildren)
    {
        RawSecurityDescriptor expectedDescriptor = CreateSecurityDescriptor(
            isDirectory,
            isSensitive,
            protectedDacl,
            inheritToChildren);
        if (!string.Equals(
                descriptor.Owner?.Value,
                expectedDescriptor.Owner?.Value,
                StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        bool isProtected = (descriptor.ControlFlags & ControlFlags.DiscretionaryAclProtected) != 0;
        if (isProtected != protectedDacl ||
            descriptor.DiscretionaryAcl is null ||
            expectedDescriptor.DiscretionaryAcl is null ||
            descriptor.DiscretionaryAcl.Count != expectedDescriptor.DiscretionaryAcl.Count)
        {
            return false;
        }

        var unmatched = descriptor.DiscretionaryAcl
            .Cast<GenericAce>()
            .ToList();
        const AceFlags inheritanceMask = AceFlags.ContainerInherit |
                                         AceFlags.ObjectInherit |
                                         AceFlags.NoPropagateInherit |
                                         AceFlags.InheritOnly;
        foreach (GenericAce expectedAce in expectedDescriptor.DiscretionaryAcl)
        {
            if (expectedAce is not QualifiedAce expectedQualified ||
                expectedQualified.AceQualifier != AceQualifier.AccessAllowed)
            {
                return false;
            }

            int matchIndex = unmatched.FindIndex(candidate =>
                candidate.GetType() == expectedAce.GetType() &&
                candidate is QualifiedAce actualQualified &&
                actualQualified.AceQualifier == expectedQualified.AceQualifier &&
                actualQualified.AccessMask == expectedQualified.AccessMask &&
                string.Equals(
                    actualQualified.SecurityIdentifier.Value,
                    expectedQualified.SecurityIdentifier.Value,
                    StringComparison.OrdinalIgnoreCase) &&
                (actualQualified.AceFlags & inheritanceMask) ==
                (expectedQualified.AceFlags & inheritanceMask));
            if (matchIndex < 0)
            {
                return false;
            }

            unmatched.RemoveAt(matchIndex);
        }

        return unmatched.Count == 0;
    }

    [SupportedOSPlatform("windows")]
    internal static bool IsProtectedEmptyDacl(RawSecurityDescriptor descriptor)
    {
        return (descriptor.ControlFlags & ControlFlags.DiscretionaryAclProtected) != 0 &&
               descriptor.DiscretionaryAcl is { Count: 0 };
    }

    [SupportedOSPlatform("windows")]
    private RawSecurityDescriptor CreateSecurityDescriptor(
        bool isDirectory,
        bool isSensitive,
        bool protectDacl,
        bool inheritToChildren)
    {
        FileSystemSecurity security = isDirectory ? new DirectorySecurity() : new FileSecurity();
        security.SetAccessRuleProtection(protectDacl, preserveInheritance: false);
        SecurityIdentifier owner = Sid(_ownerSid);
        security.SetOwner(owner);
        InheritanceFlags inheritance = isDirectory && inheritToChildren
            ? InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit
            : InheritanceFlags.None;
        AddAllowRule(security, owner, FileSystemRights.FullControl, inheritance);
        AddAllowRule(security, Sid(_administratorsSid), FileSystemRights.FullControl, inheritance);
        if (!isSensitive)
        {
            AddAllowRule(security, Sid(_readersSid), FileSystemRights.ReadAndExecute, inheritance);
        }

        return new RawSecurityDescriptor(security.GetSecurityDescriptorBinaryForm(), 0);
    }

    [SupportedOSPlatform("windows")]
    private static RawSecurityDescriptor ReadSecurityDescriptor(SafeFileHandle handle)
    {
        uint requested = OwnerSecurityInformation | DaclSecurityInformation;
        if (!GetKernelObjectSecurity(handle, requested, null, 0, out uint required))
        {
            int error = Marshal.GetLastWin32Error();
            if (error != ErrorInsufficientBuffer)
            {
                throw new Win32Exception(error, "Could not inspect the persisted data ACL.");
            }
        }

        byte[] buffer = new byte[required];
        if (!GetKernelObjectSecurity(handle, requested, buffer, required, out _))
        {
            throw new Win32Exception(Marshal.GetLastWin32Error(), "Could not inspect the persisted data ACL.");
        }

        return new RawSecurityDescriptor(buffer, 0);
    }

    [SupportedOSPlatform("windows")]
    private SafeFileHandle OpenNoFollow(
        string path,
        bool expectedDirectory)
    {
        SafeFileHandle handle = CreateFileW(
            path,
            MaximumAllowed,
            FileShareRead,
            IntPtr.Zero,
            OpenExisting,
            FileFlagBackupSemantics | FileFlagOpenReparsePoint,
            IntPtr.Zero);
        if (handle.IsInvalid)
        {
            int error = Marshal.GetLastWin32Error();
            handle.Dispose();
            throw new Win32Exception(error, $"Could not safely open Drawbridge state: {path}");
        }

        try
        {
            if (!GetFileInformationByHandle(handle, out ByHandleFileInformation information))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error(), $"Could not validate Drawbridge state: {path}");
            }

            if ((information.FileAttributes & FileAttributeReparsePoint) != 0)
            {
                throw new InvalidOperationException(
                    $"Refusing to follow a reparse point in the protected data directory: {path}");
            }

            bool isDirectory = (information.FileAttributes & FileAttributeDirectory) != 0;
            if (isDirectory != expectedDirectory)
            {
                throw new InvalidOperationException($"Unexpected filesystem object in Drawbridge state: {path}");
            }

            if (!isDirectory && information.NumberOfLinks != 1)
            {
                throw new InvalidOperationException(
                    $"Refusing to change the ACL of a hard-linked Drawbridge state file: {path}");
            }

            string expectedPath = Path.TrimEndingDirectorySeparator(Path.GetFullPath(path));
            string finalPath = Path.TrimEndingDirectorySeparator(GetFinalPath(handle));
            if (!string.Equals(finalPath, expectedPath, StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidOperationException(
                    $"Drawbridge state resolved outside its expected path: {expectedPath} -> {finalPath}");
            }

            return handle;
        }
        catch
        {
            handle.Dispose();
            throw;
        }
    }

    [SupportedOSPlatform("windows")]
    private static string GetFinalPath(SafeFileHandle handle)
    {
        uint required = GetFinalPathNameByHandleW(handle, null, 0, 0);
        if (required == 0)
        {
            throw new Win32Exception(Marshal.GetLastWin32Error(), "Could not resolve Drawbridge state identity.");
        }

        var buffer = new StringBuilder(checked((int)required + 1));
        uint written = GetFinalPathNameByHandleW(handle, buffer, (uint)buffer.Capacity, 0);
        if (written == 0 || written >= buffer.Capacity)
        {
            throw new Win32Exception(Marshal.GetLastWin32Error(), "Could not resolve Drawbridge state identity.");
        }

        string value = buffer.ToString();
        if (value.StartsWith(@"\\?\UNC\", StringComparison.OrdinalIgnoreCase))
        {
            value = @"\\" + value[8..];
        }
        else if (value.StartsWith(@"\\?\", StringComparison.Ordinal))
        {
            value = value[4..];
        }

        return Path.GetFullPath(value);
    }

    [SupportedOSPlatform("windows")]
    private void RejectRootReparsePoint()
    {
        uint attributes = GetFileAttributesW(RootDirectory);
        if (attributes == InvalidFileAttributes)
        {
            throw new Win32Exception(Marshal.GetLastWin32Error(), "Could not inspect the Drawbridge data directory.");
        }

        if ((attributes & FileAttributeReparsePoint) != 0)
        {
            throw new InvalidOperationException("The Drawbridge data directory must not be a reparse point.");
        }

        if ((attributes & FileAttributeDirectory) == 0)
        {
            throw new InvalidOperationException("The Drawbridge data path is not a directory.");
        }
    }

    [SupportedOSPlatform("windows")]
    private static bool EntryExistsNoFollow(string path)
    {
        uint attributes = GetFileAttributesW(path);
        if (attributes != InvalidFileAttributes)
        {
            return true;
        }

        int error = Marshal.GetLastWin32Error();
        if (error is ErrorFileNotFound or ErrorPathNotFound)
        {
            return false;
        }

        throw new Win32Exception(error, "Could not inspect the Drawbridge data path.");
    }

    private string ValidateContainedPath(string path)
    {
        string fullPath = Path.GetFullPath(path);
        string rootPrefix = Path.TrimEndingDirectorySeparator(RootDirectory) + Path.DirectorySeparatorChar;
        if (!fullPath.StartsWith(rootPrefix, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException("Persisted files must remain inside the Drawbridge data directory.");
        }

        return fullPath;
    }

    [SupportedOSPlatform("windows")]
    private PrivilegeScope? EnableRepairPrivilegesIfRequired() =>
        string.Equals(_ownerSid, LocalSystemSid, StringComparison.OrdinalIgnoreCase)
            ? PrivilegeScope.Enable(["SeBackupPrivilege", "SeRestorePrivilege", "SeTakeOwnershipPrivilege"])
            : null;

    [SupportedOSPlatform("windows")]
    private static SecurityIdentifier Sid(string value) => new(value);

    [SupportedOSPlatform("windows")]
    private static void AddAllowRule(
        FileSystemSecurity security,
        SecurityIdentifier identity,
        FileSystemRights rights,
        InheritanceFlags inheritanceFlags)
    {
        security.AddAccessRule(new FileSystemAccessRule(
            identity,
            rights,
            inheritanceFlags,
            PropagationFlags.None,
            AccessControlType.Allow));
    }

    [SupportedOSPlatform("windows")]
    private sealed class PrivilegeScope : IDisposable
    {
        private readonly SafeAccessTokenHandle _token;
        private readonly List<TokenPrivileges> _previousStates = [];
        private bool _disposed;

        private PrivilegeScope(SafeAccessTokenHandle token) => _token = token;

        public static PrivilegeScope Enable(IEnumerable<string> names)
        {
            using Process process = Process.GetCurrentProcess();
            if (!OpenProcessToken(
                    process.Handle,
                    TokenAdjustPrivileges | TokenQuery,
                    out SafeAccessTokenHandle token))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error(), "Could not open the service security token.");
            }

            var scope = new PrivilegeScope(token);
            try
            {
                foreach (string name in names)
                {
                    if (!LookupPrivilegeValueW(null, name, out Luid luid))
                    {
                        throw new Win32Exception(Marshal.GetLastWin32Error(), $"Could not locate {name}.");
                    }

                    var requested = new TokenPrivileges
                    {
                        PrivilegeCount = 1,
                        Privileges = new LuidAndAttributes
                        {
                            Luid = luid,
                            Attributes = SePrivilegeEnabled,
                        },
                    };
                    if (!AdjustTokenPrivilegesWithPrevious(
                            token,
                            disableAllPrivileges: false,
                            ref requested,
                            (uint)Marshal.SizeOf<TokenPrivileges>(),
                            out TokenPrivileges previous,
                            out _))
                    {
                        throw new Win32Exception(Marshal.GetLastWin32Error(), $"Could not enable {name}.");
                    }

                    if (Marshal.GetLastWin32Error() == ErrorNotAllAssigned)
                    {
                        throw new InvalidOperationException($"The service account does not hold {name}.");
                    }

                    scope._previousStates.Add(previous);
                }

                return scope;
            }
            catch
            {
                try { scope.Dispose(); } catch { }
                throw;
            }
        }

        public void Dispose()
        {
            if (_disposed)
            {
                return;
            }

            Win32Exception? restorationFailure = null;
            for (int index = _previousStates.Count - 1; index >= 0; index--)
            {
                TokenPrivileges previous = _previousStates[index];
                bool restored = AdjustTokenPrivilegesNoPrevious(
                    _token,
                    disableAllPrivileges: false,
                    ref previous,
                    0,
                    IntPtr.Zero,
                    IntPtr.Zero);
                int error = Marshal.GetLastWin32Error();
                if ((!restored || error != 0) && restorationFailure is null)
                {
                    restorationFailure = new Win32Exception(
                        error,
                        "Could not restore the service security privileges after ACL repair.");
                }
            }

            _token.Dispose();
            _disposed = true;
            if (restorationFailure is not null)
            {
                throw restorationFailure;
            }
        }
    }

    private enum SeObjectType { FileObject = 1 }

    [StructLayout(LayoutKind.Sequential)]
    private struct FileTime { public uint LowDateTime; public uint HighDateTime; }

    [StructLayout(LayoutKind.Sequential)]
    private struct ByHandleFileInformation
    {
        public uint FileAttributes;
        public FileTime CreationTime;
        public FileTime LastAccessTime;
        public FileTime LastWriteTime;
        public uint VolumeSerialNumber;
        public uint FileSizeHigh;
        public uint FileSizeLow;
        public uint NumberOfLinks;
        public uint FileIndexHigh;
        public uint FileIndexLow;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct Luid { public uint LowPart; public int HighPart; }

    [StructLayout(LayoutKind.Sequential)]
    private struct LuidAndAttributes { public Luid Luid; public uint Attributes; }

    [StructLayout(LayoutKind.Sequential)]
    private struct TokenPrivileges
    {
        public uint PrivilegeCount;
        public LuidAndAttributes Privileges;
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern SafeFileHandle CreateFileW(
        string fileName,
        uint desiredAccess,
        uint shareMode,
        IntPtr securityAttributes,
        uint creationDisposition,
        uint flagsAndAttributes,
        IntPtr templateFile);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetFileInformationByHandle(
        SafeFileHandle file,
        out ByHandleFileInformation information);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern uint GetFinalPathNameByHandleW(
        SafeFileHandle file,
        StringBuilder? filePath,
        uint filePathLength,
        uint flags);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern uint GetFileAttributesW(string fileName);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetKernelObjectSecurity(
        SafeFileHandle handle,
        uint requestedInformation,
        [Out] byte[]? securityDescriptor,
        uint length,
        out uint lengthNeeded);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern uint SetSecurityInfo(
        SafeFileHandle handle,
        SeObjectType objectType,
        uint securityInformation,
        IntPtr owner,
        IntPtr group,
        IntPtr dacl,
        IntPtr sacl);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool OpenProcessToken(
        IntPtr processHandle,
        uint desiredAccess,
        out SafeAccessTokenHandle tokenHandle);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool LookupPrivilegeValueW(string? systemName, string name, out Luid luid);

    [DllImport("advapi32.dll", EntryPoint = "AdjustTokenPrivileges", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool AdjustTokenPrivilegesWithPrevious(
        SafeAccessTokenHandle tokenHandle,
        [MarshalAs(UnmanagedType.Bool)] bool disableAllPrivileges,
        ref TokenPrivileges newState,
        uint bufferLength,
        out TokenPrivileges previousState,
        out uint returnLength);

    [DllImport("advapi32.dll", EntryPoint = "AdjustTokenPrivileges", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool AdjustTokenPrivilegesNoPrevious(
        SafeAccessTokenHandle tokenHandle,
        [MarshalAs(UnmanagedType.Bool)] bool disableAllPrivileges,
        ref TokenPrivileges newState,
        uint bufferLength,
        IntPtr previousState,
        IntPtr returnLength);
}
