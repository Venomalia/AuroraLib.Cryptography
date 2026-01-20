using AuroraLib.Cryptography.Helper;
using System.Collections.Generic;

namespace AuroraLib.Cryptography.Hash
{
    internal static class Crc32TableCache
    {
        private static readonly Dictionary<(uint Polynomial, bool Reflected), uint[]> _table_cache = new Dictionary<(uint, bool), uint[]>();

        public static uint[] GetOrCreate(uint polynomial, bool reflected)
        {
            var key = (polynomial, reflected);

            lock (_table_cache)
            {
                if (_table_cache.TryGetValue(key, out var table))
                    return table;

                table = InitializeTable(polynomial, reflected);
                _table_cache[key] = table;
                return table;
            }
        }

        private static uint[] InitializeTable(uint polynomial, bool reverse)
        {
            uint[] polynomialTable = new uint[256];
            if (reverse)
            {
                for (uint i = 0; i < 256; i++)
                {
                    uint entry;
                    entry = i << 24;
                    for (int j = 8 - 1; j >= 0; j--)
                    {
                        if ((entry & 0x80000000) != 0)
                            entry = entry << 1 ^ polynomial;
                        else
                            entry <<= 1;
                    }
                    polynomialTable[i] = entry;
                }
                return polynomialTable;
            }
            else
            {
                polynomial = BitConverterX.SwapBits(ref polynomial);
                for (uint i = 0; i < 256; i++)
                {
                    uint entry;
                    entry = i;
                    for (int j = 0; j < 8; j++)
                    {
                        if ((entry & 1) == 1)
                            entry = entry >> 1 ^ polynomial;
                        else
                            entry >>= 1;
                    }
                    polynomialTable[i] = entry;
                }
                return polynomialTable;
            }
        }
    }
}
