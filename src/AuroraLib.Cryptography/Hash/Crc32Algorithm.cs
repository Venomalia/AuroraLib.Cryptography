using System;

namespace AuroraLib.Cryptography.Hash
{
    /// <summary>
    /// Predefined CRC-32 algorithms.
    /// </summary>
    public enum Crc32Algorithm
    {
        /// <summary>Standard CRC-32 (IEEE 802.3), Used in PNG, ZIP, Ethernet, and many other formats.</summary>
        Default,
        /// <summary>CRC-32 variant used by BZIP2 compression.</summary>
        BZIP2,
        /// <summary>JAMCRC variant, same as Default but without final XOR.</summary>
        JAMCRC,
        /// <summary>CRC-32 variant used in MPEG-2 streams.</summary>
        MPEG2,
        /// <summary>CRC-32 variant used by the POSIX cksum command.</summary>
        POSIX,
        /// <summary>CRC-32 variant used for SATA (Serial ATA) storage devices.</summary>
        SATA,
        /// <summary>CRC-32 variant used for XFER (various file transfer protocols).</summary>
        XFER,
#if NET6_0_OR_GREATER
        /// <summary>
        /// CRC-32C (Castagnoli) variant, widely used in iSCSI, SCTP, and Btrfs.
        /// <para>Hardware-accelerated if <see cref="System.Runtime.Intrinsics.X86.Sse42.IsSupported"/> is <c>true</c>.</para>
        /// </summary>
#else
        /// <summary>CRC-32C (Castagnoli) variant, widely used in iSCSI, SCTP, and Btrfs.</summary>
#endif
        CRC32C,
        /// <summary>CRC-32D variant, used in some disk and communication protocols.</summary>
        CRC32D,
        /// <summary>CRC-32Q variant, used in certain networking equipment.</summary>
        CRC32Q,
    }

    internal static class Crc32Info
    {
        public static uint Polynomial(this Crc32Algorithm algorithm)
        {
            switch (algorithm)
            {
                case Crc32Algorithm.Default:
                case Crc32Algorithm.BZIP2:
                case Crc32Algorithm.JAMCRC:
                case Crc32Algorithm.MPEG2:
                case Crc32Algorithm.POSIX:
                case Crc32Algorithm.SATA:
                    return 0x04C11DB7;
                case Crc32Algorithm.XFER:
                    return 0x000000AF;
                case Crc32Algorithm.CRC32C:
                    return 0x1EDC6F41;
                case Crc32Algorithm.CRC32D:
                    return 0xA833982B;
                case Crc32Algorithm.CRC32Q:
                    return 0x814141AB;
                default:
                    throw new NotImplementedException();
            }
        }

        public static bool Reverse(this Crc32Algorithm algorithm)
        {
            switch (algorithm)
            {
                case Crc32Algorithm.BZIP2:
                case Crc32Algorithm.MPEG2:
                case Crc32Algorithm.POSIX:
                case Crc32Algorithm.SATA:
                case Crc32Algorithm.XFER:
                case Crc32Algorithm.CRC32Q:
                    return true;
                case Crc32Algorithm.Default:
                case Crc32Algorithm.JAMCRC:
                case Crc32Algorithm.CRC32C:
                case Crc32Algorithm.CRC32D:
                    return false;
                default:
                    throw new NotImplementedException();
            }
        }

        public static uint Initial(this Crc32Algorithm algorithm)
        {
            switch (algorithm)
            {
                case Crc32Algorithm.Default:
                case Crc32Algorithm.BZIP2:
                case Crc32Algorithm.JAMCRC:
                case Crc32Algorithm.MPEG2:
                case Crc32Algorithm.CRC32C:
                case Crc32Algorithm.CRC32D:
                    return 0xFFFFFFFF;
                case Crc32Algorithm.POSIX:
                case Crc32Algorithm.XFER:
                case Crc32Algorithm.CRC32Q:
                    return 0x00000000;
                case Crc32Algorithm.SATA:
                    return 0x52325032;
                default:
                    throw new NotImplementedException();
            }
        }

        public static uint XorOut(this Crc32Algorithm algorithm)
        {
            switch (algorithm)
            {
                case Crc32Algorithm.Default:
                case Crc32Algorithm.BZIP2:
                case Crc32Algorithm.POSIX:
                case Crc32Algorithm.CRC32C:
                case Crc32Algorithm.CRC32D:
                    return 0xFFFFFFFF;
                case Crc32Algorithm.JAMCRC:
                case Crc32Algorithm.MPEG2:
                case Crc32Algorithm.SATA:
                case Crc32Algorithm.XFER:
                case Crc32Algorithm.CRC32Q:
                    return 0x00000000;
                default:
                    throw new NotImplementedException();
            }
        }
    }
}
