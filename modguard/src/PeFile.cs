// WorkshopGuard ModGuard: check mods before a Unity/C# game loads them. MIT licence, github.com/CammyCodes/WorkshopGuard
using System;
using System.Collections.Generic;
using System.Text;

namespace WorkshopGuard
{
    /// <summary>Just enough of the Windows PE format to find a .NET assembly's metadata and a native DLL's imports.
    /// Reads bytes only; nothing is ever loaded or run.</summary>
    internal sealed class PeFile
    {
        public struct Section
        {
            public string Name;
            public uint VirtualAddress, VirtualSize, RawPointer, RawSize, Characteristics;
        }

        public readonly byte[] Data;
        public bool Is64;
        public readonly List<Section> Sections = new List<Section>();
        readonly uint[] dirRva = new uint[16], dirSize = new uint[16];

        PeFile(byte[] data) { Data = data; }

        public static bool LooksLikePe(byte[] d)
        {
            if (d == null || d.Length < 0x40 || d[0] != (byte)'M' || d[1] != (byte)'Z') return false;
            int off = BitConverter.ToInt32(d, 0x3C);
            return off > 0 && off + 4 <= d.Length && d[off] == (byte)'P' && d[off + 1] == (byte)'E' && d[off + 2] == 0 && d[off + 3] == 0;
        }

        /// <summary>Null if the bytes aren't a readable PE file.</summary>
        public static PeFile TryRead(byte[] d)
        {
            if (!LooksLikePe(d)) return null;
            try
            {
                var pe = new PeFile(d);
                int peOff = BitConverter.ToInt32(d, 0x3C);
                int coff = peOff + 4;
                int nSections = BitConverter.ToUInt16(d, coff + 2);
                int optSize = BitConverter.ToUInt16(d, coff + 16);
                int opt = coff + 20;
                ushort magic = BitConverter.ToUInt16(d, opt);
                if (magic != 0x10B && magic != 0x20B) return null;
                pe.Is64 = magic == 0x20B;
                int nDirsAt = opt + (pe.Is64 ? 108 : 92);
                int dirsAt = opt + (pe.Is64 ? 112 : 96);
                int nDirs = (int)Math.Min(16u, BitConverter.ToUInt32(d, nDirsAt));
                for (int i = 0; i < nDirs; i++)
                {
                    pe.dirRva[i] = BitConverter.ToUInt32(d, dirsAt + i * 8);
                    pe.dirSize[i] = BitConverter.ToUInt32(d, dirsAt + i * 8 + 4);
                }
                int sec = opt + optSize;
                for (int i = 0; i < nSections && sec + 40 <= d.Length; i++, sec += 40)
                {
                    pe.Sections.Add(new Section
                    {
                        Name = Encoding.ASCII.GetString(d, sec, 8).TrimEnd('\0'),
                        VirtualSize = BitConverter.ToUInt32(d, sec + 8),
                        VirtualAddress = BitConverter.ToUInt32(d, sec + 12),
                        RawSize = BitConverter.ToUInt32(d, sec + 16),
                        RawPointer = BitConverter.ToUInt32(d, sec + 20),
                        Characteristics = BitConverter.ToUInt32(d, sec + 36),
                    });
                }
                return pe;
            }
            catch (ArgumentException) { return null; }
            catch (IndexOutOfRangeException) { return null; }
        }

        public uint DirectoryRva(int i) { return dirRva[i]; }
        public uint DirectorySize(int i) { return dirSize[i]; }

        /// <summary>The CLI (.NET) header directory is set: this is a managed assembly.</summary>
        public bool IsDotNet { get { return dirRva[14] != 0 && dirSize[14] != 0; } }

        public int RvaToOffset(uint rva)
        {
            foreach (var s in Sections)
            {
                uint size = Math.Max(s.VirtualSize, s.RawSize);
                if (rva >= s.VirtualAddress && rva < s.VirtualAddress + size)
                {
                    long off = (long)rva - s.VirtualAddress + s.RawPointer;
                    return off >= 0 && off < Data.Length ? (int)off : -1;
                }
            }
            return rva < Data.Length && Sections.Count == 0 ? (int)rva : -1;
        }

        public byte[] SectionData(Section s, int max)
        {
            if (s.RawPointer >= Data.Length) return new byte[0];
            int n = (int)Math.Min(Math.Min(s.RawSize, (uint)max), (uint)(Data.Length - s.RawPointer));
            var b = new byte[n];
            Buffer.BlockCopy(Data, (int)s.RawPointer, b, 0, n);
            return b;
        }

        string AsciiZ(int off, int max = 512)
        {
            int end = off;
            while (end < Data.Length && end - off < max && Data[end] != 0) end++;
            return Encoding.ASCII.GetString(Data, off, end - off);
        }

        /// <summary>(dll, function) for every function a native program imports by name.</summary>
        public List<KeyValuePair<string, string>> Imports()
        {
            var outList = new List<KeyValuePair<string, string>>();
            int desc = dirRva[1] == 0 ? -1 : RvaToOffset(dirRva[1]);
            if (desc < 0) return outList;
            for (int n = 0; n < 1024 && desc + 20 <= Data.Length; n++, desc += 20)
            {
                uint lookup = BitConverter.ToUInt32(Data, desc), nameRva = BitConverter.ToUInt32(Data, desc + 12);
                uint first = BitConverter.ToUInt32(Data, desc + 16);
                if (lookup == 0 && nameRva == 0 && first == 0) break;
                int nameOff = RvaToOffset(nameRva);
                string dll = nameOff >= 0 ? AsciiZ(nameOff) : "?";
                int thunk = RvaToOffset(lookup != 0 ? lookup : first);
                int width = Is64 ? 8 : 4;
                for (int t = 0; thunk >= 0 && t < 4096 && thunk + width <= Data.Length; t++, thunk += width)
                {
                    ulong v = Is64 ? BitConverter.ToUInt64(Data, thunk) : BitConverter.ToUInt32(Data, thunk);
                    if (v == 0) break;
                    bool byOrdinal = Is64 ? (v & 0x8000000000000000UL) != 0 : (v & 0x80000000UL) != 0;
                    if (byOrdinal) continue;
                    int hint = RvaToOffset((uint)(v & 0x7FFFFFFF));
                    if (hint >= 0 && hint + 2 < Data.Length) outList.Add(new KeyValuePair<string, string>(dll, AsciiZ(hint + 2)));
                }
            }
            return outList;
        }
    }
}
