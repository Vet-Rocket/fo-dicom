// Copyright (c) 2012-2017 fo-dicom contributors.
// Licensed under the Microsoft Public License (MS-PL).

namespace Dicom
{
    using System;
    using System.Collections.Concurrent;
    using System.Collections.Generic;
    using System.Text;

    public enum DicomUidType
    {
        TransferSyntax,
        SOPClass,
        MetaSOPClass,
        ServiceClass,
        SOPInstance,
        ApplicationContextName,
        ApplicationHostingModel,
        CodingScheme,
        FrameOfReference,
        LDAP,
        MappingResource,
        ContextGroupName,
        Unknown
    }

    public enum DicomStorageCategory
    {
        None,
        Image,
        PresentationState,
        StructuredReport,
        Waveform,
        Document,
        Raw,
        Other,
        Private,
        Volume
    }

    public sealed partial class DicomUID : DicomParseable
    {
        public static string RootUID { get; set; }

        private string _uid;

        private string _name;

        private DicomUidType _type;

        private bool _retired;

        public DicomUID(string uid, string name, DicomUidType type, bool retired = false)
        {
            ValidatePathSafety(uid);
            _uid = uid;
            _name = name;
            _type = type;
            _retired = retired;
        }

        public string UID
        {
            get
            {
                return _uid;
            }
        }

        public string Name
        {
            get
            {
                return _name;
            }
        }

        public DicomUidType Type
        {
            get
            {
                return _type;
            }
        }

        public bool IsRetired
        {
            get
            {
                return _retired;
            }
        }

        public static void Register(DicomUID uid)
        {
            _uids.Add(uid.UID, uid);
        }

        public static DicomUID Generate(string name)
        {
            if (string.IsNullOrEmpty(RootUID))
            {
                RootUID = "1.2.826.0.1.3680043.2.1343.1";
            }

            var uid = $"{RootUID}.{DateTime.UtcNow.Ticks}";//weak

            return new DicomUID(uid, name, DicomUidType.SOPInstance);
        }

        public static DicomUID Generate()
        {
            var generator = new DicomUIDGenerator();
            return generator.Generate();
        }

        public static DicomUID Append(DicomUID baseUid, long nextSeq)
        {
            StringBuilder uid = new StringBuilder();
            uid.Append(baseUid.UID).Append('.').Append(nextSeq);
            return new DicomUID(uid.ToString(), "SOP Instance UID", DicomUidType.SOPInstance);
        }

        /// <summary>
        /// Validates that a UID string is safe to use as a path component.
        /// This validation is always performed regardless of DicomValidation settings.
        /// </summary>
        /// <param name="uid">The UID string to validate.</param>
        /// <exception cref="DicomDataException">Thrown when the UID contains unsafe characters or patterns.</exception>
        private static void ValidatePathSafety(string uid)
        {
            if (string.IsNullOrEmpty(uid))
            {
                // Allow empty/null for internal use (will be caught by DICOM validation if needed)
                return;
            }

            string trimmedUid = uid.TrimEnd(' ', '\0');

            // First, ensure only valid UID characters (digits and dots)
            foreach (char c in trimmedUid)
            {
                if (c != '.' && !Char.IsDigit(c))
                {
                    throw new DicomDataException(
                        $"Invalid UID '{uid}': contains invalid character '{c}'. UIDs must contain only digits (0-9) and dots (.)");
                }
            }

            // Prevent path traversal with consecutive dots
            if (trimmedUid.Contains(".."))
            {
                throw new DicomDataException(
                    $"Invalid UID '{uid}': contains consecutive dots '..' which could create unsafe path traversal when used in file paths");
            }

            // Prevent leading dot (creates hidden files/folders on Unix)
            if (trimmedUid.StartsWith("."))
            {
                throw new DicomDataException(
                    $"Invalid UID '{uid}': starts with '.' which could create hidden directories or invalid paths when used in file paths");
            }

            // Prevent trailing dot (invalid on Windows)
            if (trimmedUid.EndsWith("."))
            {
                throw new DicomDataException(
                    $"Invalid UID '{uid}': ends with '.' which creates invalid paths on Windows filesystems");
            }

            // Enforce reasonable length limit (filesystem path component limit)
            if (trimmedUid.Length > 255)
            {
                throw new DicomDataException(
                    $"Invalid UID '{uid}': exceeds maximum path component length of 255 characters");
            }

            // Check for empty components (consecutive dots already caught above, but this catches edge cases)
            var components = trimmedUid.Split('.');
            foreach (var component in components)
            {
                if (string.IsNullOrEmpty(component))
                {
                    throw new DicomDataException(
                        $"Invalid UID '{uid}': contains empty component (dots without digits between them)");
                }
            }
        }

        public static bool IsValid(string uid)
        {
            if (String.IsNullOrEmpty(uid)) return false;

            try
            {
                ValidatePathSafety(uid);
                return true;
            }
            catch (DicomDataException)
            {
                return false;
            }
        }

        public static DicomUID Parse(string s)
        {
            string u = s.TrimEnd(' ', '\0');

            DicomUID uid = null;
            if (_uids.TryGetValue(u, out uid)) return uid;

            //if (!IsValid(u))
            //	throw new DicomDataException("Invalid characters in UID string ['" + u + "']");

            ValidatePathSafety(u);

            return new DicomUID(u, "Unknown", DicomUidType.Unknown);
        }

        private static IDictionary<string, DicomUID> _uids;

        static DicomUID()
        {
            _uids = new ConcurrentDictionary<string, DicomUID>();
            LoadInternalUIDs();
            LoadPrivateUIDs();
        }

        public static IEnumerable<DicomUID> Enumerate()
        {
            return _uids.Values;
        }

        public bool IsImageStorage
        {
            get
            {
                return StorageCategory == DicomStorageCategory.Image;
            }
        }

        public DicomStorageCategory StorageCategory
        {
            get
            {
                if (!UID.StartsWith("1.2.840.10008") && Type == DicomUidType.SOPClass)
                {
                    return DicomStorageCategory.Private;
                }

                if (Type != DicomUidType.SOPClass || Name.StartsWith("Storage Commitment") || !Name.Contains("Storage"))
                {
                    return DicomStorageCategory.None;
                }

                if (Name.Contains("Image Storage"))
                {
                    return DicomStorageCategory.Image;
                }

                if (Name.Contains("Volume Storage"))
                {
                    return DicomStorageCategory.Volume;
                }

                if (this == BlendingSoftcopyPresentationStateStorage
                    || this == ColorSoftcopyPresentationStateStorage
                    || this == GrayscaleSoftcopyPresentationStateStorage
                    || this == PseudoColorSoftcopyPresentationStateStorage)
                {
                    return DicomStorageCategory.PresentationState;
                }

                if (this == AudioSRStorageTrialRETIRED
                    || this == BasicTextSRStorage
                    || this == ChestCADSRStorage
                    || this == ComprehensiveSRStorage
                    || this == ComprehensiveSRStorageTrialRETIRED
                    || this == DetailSRStorageTrialRETIRED
                    || this == EnhancedSRStorage
                    || this == MammographyCADSRStorage
                    || this == TextSRStorageTrialRETIRED
                    || this == XRayRadiationDoseSRStorage)
                {
                    return DicomStorageCategory.StructuredReport;
                }

                if (this == AmbulatoryECGWaveformStorage
                    || this == BasicVoiceAudioWaveformStorage
                    || this == CardiacElectrophysiologyWaveformStorage
                    || this == GeneralECGWaveformStorage
                    || this == HemodynamicWaveformStorage
                    || this == TwelveLeadECGWaveformStorage
                    || this == WaveformStorageTrialRETIRED)
                {
                    return DicomStorageCategory.Waveform;
                }

                if (this == EncapsulatedCDAStorage
                    || this == EncapsulatedPDFStorage)
                {
                    return DicomStorageCategory.Document;
                }

                if (this == RawDataStorage)
                {
                    return DicomStorageCategory.Raw;
                }

                return DicomStorageCategory.Other;
            }
        }

        public static bool operator ==(DicomUID a, DicomUID b)
        {
            if (((object)a == null) && ((object)b == null)) return true;
            if (((object)a == null) || ((object)b == null)) return false;
            return a.UID == b.UID;
        }

        public static bool operator !=(DicomUID a, DicomUID b)
        {
            return !(a == b);
        }

        public override bool Equals(object obj)
        {
            if (ReferenceEquals(this, obj)) return true;
            if (!(obj is DicomUID)) return false;
            return (obj as DicomUID).UID == UID;
        }

        public override int GetHashCode()
        {
            return UID.GetHashCode();
        }

        public override string ToString()
        {
            return String.Format("{0} [{1}]", Name, UID);
        }
    }
}
