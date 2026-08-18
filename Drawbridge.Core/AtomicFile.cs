using System.Text;

namespace Drawbridge.Core;

internal static class AtomicFile
{
    internal static void WriteAllText(
        string path,
        string contents,
        Action<string>? prepareTemporaryFile = null)
    {
        string? directory = Path.GetDirectoryName(path);
        if (string.IsNullOrEmpty(directory))
        {
            throw new ArgumentException("The file must have a parent directory.", nameof(path));
        }

        Directory.CreateDirectory(directory);
        string temporaryPath = Path.Combine(
            directory,
            $".{Path.GetFileName(path)}.{Environment.ProcessId}.{Guid.NewGuid():N}.tmp");

        try
        {
            // Publish only an empty placeholder before applying any caller-supplied ACL.
            // Secret records (notably the PIN verifier) are therefore protected before
            // their first byte is written, rather than briefly inheriting Users read access.
            using (new FileStream(
                       temporaryPath,
                       FileMode.CreateNew,
                       FileAccess.Write,
                       FileShare.None))
            {
            }

            prepareTemporaryFile?.Invoke(temporaryPath);
            using (var stream = new FileStream(
                       temporaryPath,
                       FileMode.Truncate,
                       FileAccess.Write,
                       FileShare.None))
            using (var writer = new StreamWriter(
                       stream,
                       new UTF8Encoding(encoderShouldEmitUTF8Identifier: false)))
            {
                writer.Write(contents);
            }

            File.Move(temporaryPath, path, overwrite: true);
        }
        finally
        {
            try { File.Delete(temporaryPath); } catch { }
        }
    }
}
