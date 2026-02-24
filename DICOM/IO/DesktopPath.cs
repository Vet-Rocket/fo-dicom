// Copyright (c) 2012-2017 fo-dicom contributors.
// Licensed under the Microsoft Public License (MS-PL).

using System;

namespace Dicom.IO
{
    using System.IO;

    /// <summary>
    /// .NET/Windows Desktop implementation of the <see cref="IPath"/> interface.
    /// </summary>
    public class DesktopPath : IPath
    {
        #region FIELDS

        /// <summary>
        /// Single instance of the <see cref="DesktopPath"/> class.
        /// </summary>
        public static readonly IPath Instance;

        #endregion

        #region CONSTRUCTORS

        /// <summary>
        /// Initializes the static members of <see cref="DesktopPath"/>.
        /// </summary>
        static DesktopPath()
        {
            Instance = new DesktopPath();
        }

        /// <summary>
        /// Initializes a <see cref="DesktopPath"/> object.
        /// </summary>
        private DesktopPath()
        {
        }

        #endregion

        #region METHODS

        /// <summary>
        /// Returns the directory information for the specified path string.
        /// </summary>
        /// <param name="path">The path of a file or directory.</param>
        /// <returns>
        /// Directory information for path, or null if path denotes a root directory or is null. 
        /// Returns <see cref="string.Empty"/> if path does not contain directory information.
        /// </returns>
        public string GetDirectoryName(string path)
        {
            return Path.GetDirectoryName(path);
        }

        /// <summary>
        /// Returns the path of the current user's temporary folder.
        /// </summary>
        /// <returns>The path to the temporary folder, ending with a backslash.</returns>
        public string GetTempDirectory()
        {
            return Path.GetTempPath();
        }

        /// <summary>
        /// Creates a uniquely named, zero-byte temporary file on disk and returns the full path of that file.
        /// </summary>
        /// <returns>The full path of the temporary file.</returns>
        public string GetTempFileName()
        {
            return Path.GetTempFileName();
        }

        /// <summary>
        /// Combines an array of strings into a path.
        /// </summary>
        /// <param name="paths">An array of parts of the path.</param>
        /// <returns>The combined paths.</returns>
        public string Combine(params string[] paths)
        {
            if (paths == null)
            {
                throw new ArgumentNullException(nameof(paths));
            }

#if NET35
            var combined = string.Empty;
            foreach (var path in paths)
            {
                combined = Path.Combine(combined, path);
            }

            return combined;
#else
            if (paths.Length == 0)
            {
                throw new ArgumentException("At least one path segment must be provided.", nameof(paths));
            }

            // The first segment is treated as the root.
            string root = paths[0];
            string[] segments;
            if (paths.Length > 1)
            {
                segments = new string[paths.Length - 1];
                Array.Copy(paths, 1, segments, 0, paths.Length - 1);
            }
            else
            {
                segments = new string[0];
            }

            return SafeCombine(root, segments);
#endif
        }

        #endregion

        /// <summary>
        /// Combines path segments like Path.Combine, but enforces that:
        /// 1. The first segment is an absolute/rooted path (including UNC paths like \\server\share).
        /// 2. All subsequent segments are safe — they must not be rooted, must not contain '..'
        ///    directory traversal sequences, and must not contain any directory separator characters
        ///    that could escape the root.
        /// </summary>
        /// <exception cref="ArgumentException">
        /// Thrown if the root is not rooted, or if any subsequent segment attempts path traversal.
        /// </exception>
        public static string SafeCombine(string root, params string[] segments)
        {
            if (string.IsNullOrEmpty(root))
                throw new ArgumentException("Root path must not be null or empty.", nameof(root));

            if (!Path.IsPathRooted(root))
                throw new ArgumentException($"Root path must be an absolute path. Got: '{root}'", nameof(root));

            foreach (var segment in segments)
            {
                if (segment == null)
                    throw new ArgumentNullException(nameof(segments), "Path segments must not be null.");

                EnsureSegmentIsSafe(segment);
            }

            string[] allSegments = new string[1 + segments.Length];
            allSegments[0] = root;
            for (int i = 0; i < segments.Length; i++)
            {
                allSegments[i + 1] = segments[i];
            }
            string combined = Path.Combine(allSegments);

            // Normalize both paths before comparing, so that things like double separators,
            // '.' components, and symlink-free traversal attempts are resolved first.
            string normalizedCombined = Path.GetFullPath(combined);
            string normalizedRoot = Path.GetFullPath(root);

            // Ensure the result is still within the root. The trailing separator on normalizedRoot
            // is critical — without it, a root of "C:\uploads" would incorrectly accept
            // "C:\uploads-evil\file.txt" since that string also starts with "C:\uploads".
            if (!normalizedCombined.StartsWith(
                    normalizedRoot.TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar,
                    StringComparison.OrdinalIgnoreCase))
                throw new ArgumentException(
                    $"Combined path '{combined}' resolves outside of root '{root}'.");

            return normalizedCombined;
        }

        private static void EnsureSegmentIsSafe(string segment)
        {
            // Reject rooted segments — these would cause SafePath.CombinePath to discard the root entirely.
            // e.g. SafePath.CombinePath(@"C:\safe", @"C:\evil") => @"C:\evil"
            if (Path.IsPathRooted(segment))
                throw new ArgumentException(
                    $"Path segment must not be rooted. Got: '{segment}'", nameof(segment));

            // Reject segments containing directory separators. Combined with the rooting check above,
            // this prevents traversal via e.g. "subdir/../../etc". We're strict here: each segment
            // should be a single file or directory name, not a sub-path.
            // 
            // If you want to allow sub-paths like "subdir/child", use the alternative check below.
            //if (segment.Contains(Path.DirectorySeparatorChar) ||
            //    segment.Contains(Path.AltDirectorySeparatorChar))
            //    throw new ArgumentException(
            //        $"Path segment must not contain directory separators. Got: '{segment}'", nameof(segment));

            // Belt-and-suspenders: explicitly reject '..' even without separators.
            // Also reject '.' as it's unnecessary and potentially confusing.
            if (segment == ".." || segment == ".")
                throw new ArgumentException(
                    $"Path segment must not be a relative directory reference. Got: '{segment}'", nameof(segment));

            // Reject any characters that are invalid in file/path names on the current OS.
            char[] invalidChars = Path.GetInvalidFileNameChars();
            int invalidIndex = segment.IndexOfAny(invalidChars);
            if (invalidIndex >= 0)
                throw new ArgumentException(
                    $"Path segment contains invalid character '{segment[invalidIndex]}' at index {invalidIndex}. Got: '{segment}'", nameof(segment));
        }
    }
}
