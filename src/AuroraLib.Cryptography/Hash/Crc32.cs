using AuroraLib.Cryptography.Helper;
using AuroraLib.Interfaces;
using System;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
#if NET6_0_OR_GREATER
using System.Runtime.Intrinsics.X86;
#endif

namespace AuroraLib.Cryptography.Hash
{
    /// <summary>
    /// Represents a CRC-32 hash algorithm.
    /// </summary>
    public sealed class Crc32 : IHash<uint>
    {
        /// <inheritdoc />
        public uint Value => _value ^ _xorOut;
        private uint _value;

        /// <inheritdoc />
        public int ByteSize => 4;

        private readonly uint _init;
        private readonly uint _xorOut;
        private readonly bool _reflected;
        private readonly uint[] _table;
#if NET6_0_OR_GREATER
        private readonly bool _is_nativ_crc32c;
#endif

        /// <summary>
        /// Initializes a new instance of the <see cref="Crc32"/> class.
        /// </summary>
        /// <param name="polynomial">The polynomial used for CRC calculation.</param>
        /// <param name="reflected">Use reflected calculation.</param>
        /// <param name="initial">The initial value for the CRC calculation.</param>
        /// <param name="xorOut">The XOR output value for the CRC calculation.</param>
        public Crc32(uint polynomial, bool reflected = false, uint initial = uint.MaxValue, uint xorOut = uint.MaxValue)
        {
            _reflected = reflected;
            _init = initial;
            _value = initial;
            _xorOut = xorOut;

#if NET6_0_OR_GREATER
            _is_nativ_crc32c = polynomial == Crc32Algorithm.CRC32C.Polynomial() && reflected == Crc32Algorithm.CRC32C.Reverse() && Sse42.IsSupported;

            if (!_is_nativ_crc32c)
                _table = Crc32TableCache.GetOrCreate(polynomial, reflected);
#else
            _table = Crc32TableCache.GetOrCreate(polynomial, reflected);
#endif
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="Crc32"/> class with the specified <see cref="Crc32Algorithm"/>.
        /// </summary>
        /// <param name="alg">The CRC-32 algorithm to use.</param>
        /// <remarks>
        /// This constructor simplifies the creation of a <see cref="Crc32"/> instance by providing a high-level interface
        /// that abstracts the specific CRC-32 algorithm details. It internally retrieves the polynomial, reverse, initial,
        /// and xorOut values associated with the specified algorithm and initializes the <see cref="Crc32"/> instance using
        /// those values.
        /// </remarks>
        public Crc32(Crc32Algorithm alg) : this(alg.Polynomial(), alg.Reverse(), alg.Initial(), alg.XorOut())
        { }

        ///  <inheritdoc cref="Crc32(uint, bool, uint, uint)"/>
        public Crc32() : this(Crc32Algorithm.Default)
        { }

        /// <inheritdoc />
        public void Compute(ReadOnlySpan<byte> input)
        {
            uint crc = _value;
#if NET6_0_OR_GREATER
            if (_is_nativ_crc32c)
            {
                if (input.Length >= 4)
                {
                    var ints = MemoryMarshal.Cast<byte, uint>(input);
                    foreach (var i in ints)
                        crc = Sse42.Crc32(crc, i);
                    input = input[(ints.Length * 4)..];
                }
                foreach (byte b in input)
                    crc = Sse42.Crc32(crc, b);
            }
            else
#endif
            {
                if (_reflected)
                {
                    foreach (byte b in input)
                    {
                        crc = (crc << 8) ^ _table[((crc >> 24) ^ b) & 0xFF];
                    }
                }
                else
                {
                    foreach (byte b in input)
                    {
                        crc = (crc >> 8) ^ _table[(crc ^ b) & 0xFF];
                    }
                }
            }
            _value = crc;
        }

        /// <inheritdoc />
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public byte[] GetBytes()
            => BitConverterX.GetBytes(Value);

        /// <inheritdoc />
        public void Write(Span<byte> destination)
        {
            uint value = Value;
            MemoryMarshal.Write(destination, ref value);
        }

        /// <inheritdoc />
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public void Reset()
            => _value = _init;

        /// <inheritdoc />
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public void SetSeed(uint seed)
            => _value = seed;
    }
}
