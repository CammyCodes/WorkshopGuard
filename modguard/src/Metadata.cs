// WorkshopGuard ModGuard: check mods before a Unity/C# game loads them. MIT licence, github.com/CammyCodes/WorkshopGuard
using System;
using System.Collections.Generic;
using System.Text;

namespace WorkshopGuard
{
    /// <summary>A small, read-only ECMA-335 metadata reader: just the tables and heaps the analyzer needs (type and
    /// member references, P/Invoke imports, type names, string literals, embedded resources). It never loads the
    /// assembly, so a hostile mod's code can't run, and it has no dependency beyond the base class library.</summary>
    internal sealed class Metadata
    {
        // ECMA-335 II.22 table numbers used here
        const int Module = 0x00, TypeRef = 0x01, TypeDef = 0x02, Field = 0x04, MethodDef = 0x06, Param = 0x08,
                  InterfaceImpl = 0x09, MemberRef = 0x0A, DeclSecurity = 0x0E, Event = 0x14, Property = 0x17,
                  StandAloneSig = 0x11, ModuleRef = 0x1A, TypeSpec = 0x1B, ImplMap = 0x1C, Assembly = 0x20,
                  AssemblyRef = 0x23, File = 0x26, ExportedType = 0x27, ManifestResource = 0x28,
                  GenericParam = 0x2A, MethodSpec = 0x2B, GenericParamConstraint = 0x2C;
        const int TableCount = 0x2D;

        // Column kinds: fixed sizes are 2 or 4; others are heap/table/coded indexes resolved per assembly.
        const int U2 = -2, U4 = -4, Str = -10, Guid = -11, Blob = -12;
        const int CodedBase = 1000;   // CodedBase + coded index kind; plain table index = table number (0..63)
        const int TypeDefOrRef = 0, HasConstant = 1, HasCustomAttribute = 2, HasFieldMarshal = 3, HasDeclSecurity = 4,
                  MemberRefParent = 5, HasSemantics = 6, MethodDefOrRef = 7, MemberForwarded = 8, Implementation = 9,
                  CustomAttributeType = 10, ResolutionScope = 11, TypeOrMethodDef = 12;

        static readonly int[][] CodedTables =
        {
            new[] { TypeDef, TypeRef, TypeSpec },
            new[] { Field, Param, Property },
            new[] { MethodDef, Field, TypeRef, TypeDef, Param, InterfaceImpl, MemberRef, Module, DeclSecurity, Property,
                    Event, StandAloneSig, ModuleRef, TypeSpec, Assembly, AssemblyRef, File, ExportedType,
                    ManifestResource, GenericParam, GenericParamConstraint, MethodSpec },
            new[] { Field, Param },
            new[] { TypeDef, MethodDef, Assembly },
            new[] { TypeDef, TypeRef, ModuleRef, MethodDef, TypeSpec },
            new[] { Event, Property },
            new[] { MethodDef, MemberRef },
            new[] { Field, MethodDef },
            new[] { File, AssemblyRef, ExportedType },
            new[] { -1, -1, MethodDef, MemberRef, -1 },
            new[] { Module, ModuleRef, AssemblyRef, TypeRef },
            new[] { TypeDef, MethodDef },
        };
        static readonly int[] CodedTagBits = { 2, 2, 5, 1, 2, 3, 1, 1, 1, 2, 3, 2, 1 };

        static int C(int kind) { return CodedBase + kind; }

        // ECMA-335 II.22: the columns of every table that can appear in an assembly, in order.
        static readonly int[][] Schema =
        {
            /*00 Module*/ new[] { U2, Str, Guid, Guid, Guid },
            /*01 TypeRef*/ new[] { C(ResolutionScope), Str, Str },
            /*02 TypeDef*/ new[] { U4, Str, Str, C(TypeDefOrRef), Field, MethodDef },
            /*03 FieldPtr*/ new[] { Field },
            /*04 Field*/ new[] { U2, Str, Blob },
            /*05 MethodPtr*/ new[] { MethodDef },
            /*06 MethodDef*/ new[] { U4, U2, U2, Str, Blob, Param },
            /*07 ParamPtr*/ new[] { Param },
            /*08 Param*/ new[] { U2, U2, Str },
            /*09 InterfaceImpl*/ new[] { TypeDef, C(TypeDefOrRef) },
            /*0A MemberRef*/ new[] { C(MemberRefParent), Str, Blob },
            /*0B Constant*/ new[] { U2, C(HasConstant), Blob },
            /*0C CustomAttribute*/ new[] { C(HasCustomAttribute), C(CustomAttributeType), Blob },
            /*0D FieldMarshal*/ new[] { C(HasFieldMarshal), Blob },
            /*0E DeclSecurity*/ new[] { U2, C(HasDeclSecurity), Blob },
            /*0F ClassLayout*/ new[] { U2, U4, TypeDef },
            /*10 FieldLayout*/ new[] { U4, Field },
            /*11 StandAloneSig*/ new[] { Blob },
            /*12 EventMap*/ new[] { TypeDef, Event },
            /*13 EventPtr*/ new[] { Event },
            /*14 Event*/ new[] { U2, Str, C(TypeDefOrRef) },
            /*15 PropertyMap*/ new[] { TypeDef, Property },
            /*16 PropertyPtr*/ new[] { Property },
            /*17 Property*/ new[] { U2, Str, Blob },
            /*18 MethodSemantics*/ new[] { U2, MethodDef, C(HasSemantics) },
            /*19 MethodImpl*/ new[] { TypeDef, C(MethodDefOrRef), C(MethodDefOrRef) },
            /*1A ModuleRef*/ new[] { Str },
            /*1B TypeSpec*/ new[] { Blob },
            /*1C ImplMap*/ new[] { U2, C(MemberForwarded), Str, ModuleRef },
            /*1D FieldRVA*/ new[] { U4, Field },
            /*1E EncLog*/ new[] { U4, U4 },
            /*1F EncMap*/ new[] { U4 },
            /*20 Assembly*/ new[] { U4, U2, U2, U2, U2, U4, Blob, Str, Str },
            /*21 AssemblyProcessor*/ new[] { U4 },
            /*22 AssemblyOS*/ new[] { U4, U4, U4 },
            /*23 AssemblyRef*/ new[] { U2, U2, U2, U2, U4, Blob, Str, Str, Blob },
            /*24 AssemblyRefProcessor*/ new[] { U4, AssemblyRef },
            /*25 AssemblyRefOS*/ new[] { U4, U4, U4, AssemblyRef },
            /*26 File*/ new[] { U4, Str, Blob },
            /*27 ExportedType*/ new[] { U4, U4, Str, Str, C(Implementation) },
            /*28 ManifestResource*/ new[] { U4, U4, Str, C(Implementation) },
            /*29 NestedClass*/ new[] { TypeDef, TypeDef },
            /*2A GenericParam*/ new[] { U2, U2, C(TypeOrMethodDef), Str },
            /*2B MethodSpec*/ new[] { C(MethodDefOrRef), Blob },
            /*2C GenericParamConstraint*/ new[] { GenericParam, C(TypeDefOrRef) },
        };

        readonly byte[] d;
        readonly PeFile pe;
        int stringsOff, stringsSize, usOff, usSize, blobOff, blobSize;
        int strIdx = 2, guidIdx = 2, blobIdx = 2;
        readonly int[] rows = new int[64];
        readonly int[] tableOff = new int[64];
        readonly int[] rowSize = new int[64];
        readonly int[][] colOff = new int[64][];
        readonly int[][] colSize = new int[64][];

        Metadata(PeFile pe) { this.pe = pe; d = pe.Data; }

        /// <summary>Reads a .NET assembly's metadata. Throws <see cref="FormatException"/> if it's malformed.</summary>
        public static Metadata Read(PeFile pe)
        {
            var m = new Metadata(pe);
            try { m.Parse(); }
            catch (ArgumentException e) { throw new FormatException("bad metadata: " + e.Message); }
            catch (IndexOutOfRangeException) { throw new FormatException("metadata runs past the end of the file"); }
            return m;
        }

        uint U32(int o) { return BitConverter.ToUInt32(d, o); }
        ushort U16(int o) { return BitConverter.ToUInt16(d, o); }

        void Parse()
        {
            int cli = pe.RvaToOffset(pe.DirectoryRva(14));
            if (cli < 0) throw new FormatException("no CLI header");
            int root = pe.RvaToOffset(U32(cli + 8));
            if (root < 0 || U32(root) != 0x424A5342) throw new FormatException("no metadata root");
            int verLen = (int)U32(root + 12);
            int p = root + 16 + verLen;
            int streams = U16(p + 2);
            p += 4;
            int tablesOff = -1;
            for (int i = 0; i < streams; i++)
            {
                int off = (int)U32(p), size = (int)U32(p + 4);
                int nameStart = p + 8, nameEnd = nameStart;
                while (d[nameEnd] != 0) nameEnd++;
                string name = Encoding.ASCII.GetString(d, nameStart, nameEnd - nameStart);
                p = nameStart + ((nameEnd - nameStart + 4) & ~3);
                int at = root + off;
                if (name == "#~" || name == "#-") tablesOff = at;
                else if (name == "#Strings") { stringsOff = at; stringsSize = size; }
                else if (name == "#US") { usOff = at; usSize = size; }
                else if (name == "#Blob") { blobOff = at; blobSize = size; }
            }
            if (tablesOff < 0) throw new FormatException("no metadata tables");

            byte heapSizes = d[tablesOff + 6];
            if ((heapSizes & 1) != 0) strIdx = 4;
            if ((heapSizes & 2) != 0) guidIdx = 4;
            if ((heapSizes & 4) != 0) blobIdx = 4;
            ulong valid = BitConverter.ToUInt64(d, tablesOff + 8);
            p = tablesOff + 24;
            for (int t = 0; t < 64; t++)
            {
                if ((valid & (1UL << t)) == 0) continue;
                if (t >= TableCount) throw new FormatException("unexpected metadata table 0x" + t.ToString("x2"));
                rows[t] = (int)U32(p);
                p += 4;
            }
            if ((heapSizes & 0x40) != 0) p += 4;   // extra data (edit-and-continue builds)

            for (int t = 0; t < TableCount; t++)
            {
                var cols = Schema[t];
                colOff[t] = new int[cols.Length];
                colSize[t] = new int[cols.Length];
                int size = 0;
                for (int c = 0; c < cols.Length; c++)
                {
                    colOff[t][c] = size;
                    colSize[t][c] = ColumnSize(cols[c]);
                    size += colSize[t][c];
                }
                rowSize[t] = size;
                tableOff[t] = p;
                p += size * rows[t];
            }
            if (p > d.Length) throw new FormatException("metadata tables run past the end of the file");
        }

        int ColumnSize(int kind)
        {
            if (kind == U2) return 2;
            if (kind == U4) return 4;
            if (kind == Str) return strIdx;
            if (kind == Guid) return guidIdx;
            if (kind == Blob) return blobIdx;
            if (kind >= CodedBase)
            {
                int ck = kind - CodedBase, max = 0;
                foreach (int t in CodedTables[ck]) if (t >= 0) max = Math.Max(max, rows[t]);
                return max < (1 << (16 - CodedTagBits[ck])) ? 2 : 4;
            }
            return rows[kind] < 0x10000 ? 2 : 4;
        }

        public int Rows(int table) { return rows[table]; }

        int Col(int table, int row, int col)   // row is 1-based, as in tokens
        {
            int o = tableOff[table] + (row - 1) * rowSize[table] + colOff[table][col];
            return colSize[table][col] == 2 ? U16(o) : (int)U32(o);
        }

        void Coded(int kind, int value, out int table, out int row)
        {
            int bits = CodedTagBits[kind];
            int tag = value & ((1 << bits) - 1);
            table = tag < CodedTables[kind].Length ? CodedTables[kind][tag] : -1;
            row = value >> bits;
        }

        public string String(int idx)
        {
            if (idx <= 0 || idx >= stringsSize) return "";
            int s = stringsOff + idx, e = s;
            int limit = stringsOff + stringsSize;
            while (e < limit && d[e] != 0) e++;
            return Encoding.UTF8.GetString(d, s, e - s);
        }

        public byte[] BlobAt(int idx)
        {
            if (idx <= 0 || idx >= blobSize) return new byte[0];
            int p = blobOff + idx;
            int len = CompressedUInt(d, ref p);
            if (len < 0 || p + len > blobOff + blobSize) return new byte[0];
            var b = new byte[len];
            Buffer.BlockCopy(d, p, b, 0, len);
            return b;
        }

        /// <summary>ECMA-335 II.23.2 compressed unsigned integer; advances <paramref name="p"/>.</summary>
        public static int CompressedUInt(byte[] b, ref int p)
        {
            byte x = b[p];
            if ((x & 0x80) == 0) { p += 1; return x; }
            if ((x & 0xC0) == 0x80) { int v = ((x & 0x3F) << 8) | b[p + 1]; p += 2; return v; }
            int w = ((x & 0x1F) << 24) | (b[p + 1] << 16) | (b[p + 2] << 8) | b[p + 3];
            p += 4;
            return w;
        }

        // --- what the analyzer asks for ----------------------------------------------------------------------------

        /// <summary>"Namespace.Type" for a TypeRef row, nested types as "Outer+Inner" (same as dnfile's view).</summary>
        public string TypeRefName(int row, int depth = 0)
        {
            if (row <= 0 || row > rows[TypeRef] || depth > 8) return "?";
            string name = String(Col(TypeRef, row, 1)), ns = String(Col(TypeRef, row, 2));
            if (ns.Length == 0)
            {
                int t, r;
                Coded(ResolutionScope, Col(TypeRef, row, 0), out t, out r);
                if (t == TypeRef) return TypeRefName(r, depth + 1) + "+" + name;
            }
            return ns.Length > 0 ? ns + "." + name : name;
        }

        /// <summary>("Namespace.Type::Method", signature blob) for every member reference.</summary>
        public IEnumerable<KeyValuePair<string, byte[]>> MemberRefs()
        {
            for (int r = 1; r <= rows[MemberRef]; r++)
            {
                int t, row;
                Coded(MemberRefParent, Col(MemberRef, r, 0), out t, out row);
                string owner = t == TypeRef ? TypeRefName(row) : "?";
                yield return new KeyValuePair<string, byte[]>(owner + "::" + String(Col(MemberRef, r, 1)),
                                                              BlobAt(Col(MemberRef, r, 2)));
            }
        }

        /// <summary>(native dll, function) for every P/Invoke.</summary>
        public IEnumerable<KeyValuePair<string, string>> PInvokes()
        {
            for (int r = 1; r <= rows[ImplMap]; r++)
            {
                int scope = Col(ImplMap, r, 3);
                string dll = scope >= 1 && scope <= rows[ModuleRef] ? String(Col(ModuleRef, scope, 0)) : "?";
                yield return new KeyValuePair<string, string>(dll, String(Col(ImplMap, r, 2)));
            }
        }

        public IEnumerable<string> TypeNames()
        {
            for (int r = 1; r <= rows[TypeDef]; r++) yield return String(Col(TypeDef, r, 1));
            for (int r = 1; r <= rows[TypeRef]; r++) yield return String(Col(TypeRef, r, 1));
        }

        /// <summary>Every string literal in the code (the #US heap).</summary>
        public IEnumerable<string> UserStrings()
        {
            int p = 1;
            while (p < usSize)
            {
                int at = usOff + p;
                int len;
                try { len = CompressedUInt(d, ref at); }
                catch (IndexOutOfRangeException) { yield break; }
                if (len <= 0) { p = at - usOff; if (len == 0) continue; yield break; }
                int chars = len - (len & 1);   // the last byte is a flag when the length is odd
                if (at + chars > usOff + usSize) yield break;
                if (chars > 0) yield return Encoding.Unicode.GetString(d, at, chars);
                p = at - usOff + len;
            }
        }

        /// <summary>(name, first bytes) of every resource embedded in the assembly.</summary>
        public IEnumerable<KeyValuePair<string, byte[]>> EmbeddedResources(int headBytes = 4)
        {
            int cli = pe.RvaToOffset(pe.DirectoryRva(14));
            uint resRva = U32(cli + 24);
            int resBase = resRva == 0 ? -1 : pe.RvaToOffset(resRva);
            for (int r = 1; r <= rows[ManifestResource]; r++)
            {
                if (Col(ManifestResource, r, 3) != 0 || resBase < 0) continue;   // linked from another file
                int at = resBase + Col(ManifestResource, r, 0);
                if (at < 0 || at + 4 > d.Length) continue;
                int len = (int)U32(at);
                int n = Math.Max(0, Math.Min(Math.Min(len, headBytes), d.Length - at - 4));
                var head = new byte[n];
                Buffer.BlockCopy(d, at + 4, head, 0, n);
                yield return new KeyValuePair<string, byte[]>(String(Col(ManifestResource, r, 2)), head);
            }
        }
    }
}
