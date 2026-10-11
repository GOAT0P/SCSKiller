# Throwaway diagnostic for PUBG (not for upstream): walks a pak's entries from byte 0 without its encrypted index,
# decompresses them with the Oodle DLL SCSKiller's build downloaded, and counts what is inside. Reads files only.
param([string]$Paks = "C:\Program Files (x86)\Steam\steamapps\common\PUBG\TslGame\Content\Paks", [int]$Seconds = 60,
      [string[]]$Names = @("pakchunk0-WindowsNoEditor.pak", "pakchunk0-WindowsNoEditor_etc.pak", "pakchunk0-WindowsNoEditor_fx.pak",
                           "pakchunk0-WindowsNoEditor_bps.pak", "pakchunk0-WindowsNoEditor_assets_world.pak", "pakchunk0-WindowsNoEditor_mutable.pak"))
$oodle = Join-Path $env:LOCALAPPDATA "SCSKiller-build\codecs\oodle-data-shared.dll"
if (-not (Test-Path $oodle)) { throw "no $oodle : run build\publish.ps1 once first" }
$src = @'
using System; using System.IO; using System.IO.Compression; using System.Runtime.InteropServices; using System.Collections.Generic; using System.Diagnostics; using System.Text;
public static class PakWalk {
  [DllImport(@"oodle-not-used")] static extern long OodleLZ_Decompress(byte[] src, long srcLen, byte[] dst, long dstLen, int fuzz, int crc, int verb, IntPtr a, long b, IntPtr c, IntPtr d, IntPtr e, long f, int g);
  static int Count(byte[] b, int n, byte[] pat) { int c = 0; for (int i = 0; i + pat.Length <= n; i++) { int k = 0; while (k < pat.Length && b[i + k] == pat[k]) k++; if (k == pat.Length) c++; } return c; }
  static readonly byte[] Dxbc = Encoding.ASCII.GetBytes("DXBC"), Tag = { 0xC1, 0x83, 0x2A, 0x9E }, Zlib = { 0x78, 0x9C };
  public static string Walk(string path, int maxSec) {
    var sw = Stopwatch.StartNew(); var sb = new StringBuilder(); var methods = new SortedDictionary<int, int>();
    long entries = 0, encrypted = 0, failed = 0, packages = 0, dxbc = 0, withDxbc = 0, zlibInPackages = 0, skipped = 0, pos = 0;
    string stop = "end of data", first = "";
    using (var f = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete)) {
      var r = new BinaryReader(f);
      f.Seek(-45, SeekOrigin.End); var fb = r.ReadBytes(45);
      if (BitConverter.ToUInt32(fb, 1) != 0x5A6F12E1) return Path.GetFileName(path) + ": no v4 footer";
      long dataEnd = BitConverter.ToInt64(fb, 9);
      while (pos < dataEnd) {
        if (sw.Elapsed.TotalSeconds > maxSec) { stop = "time limit"; break; }
        f.Seek(pos, SeekOrigin.Begin);
        long off = r.ReadInt64(), size = r.ReadInt64(), usize = r.ReadInt64(); int method = r.ReadInt32(); r.ReadBytes(20);
        if (size < 0 || usize < 0 || size > dataEnd || usize > (1L << 32)) { stop = string.Format("bad header at {0}", pos); break; }
        var blocks = new List<long[]>();
        if (method != 0) { int n = r.ReadInt32(); if (n < 0 || n > 1000000) { stop = string.Format("bad block count {0} at {1}", n, pos); break; } for (int i = 0; i < n; i++) blocks.Add(new[] { r.ReadInt64(), r.ReadInt64() }); }
        int enc = r.ReadByte(); uint bs = r.ReadUInt32(); long hdr = f.Position - pos;
        if (entries < 2) first += string.Format(" [entry {0}: offset field {1}, header {2} B, first block at {3}]", entries, off, hdr, blocks.Count > 0 ? blocks[0][0] : -1);
        entries++; int m; methods[method] = methods.TryGetValue(method, out m) ? m + 1 : 1;
        bool rel = blocks.Count > 0 && blocks[0][0] < pos;  // v5+: offsets from the entry
        long next = method == 0 ? pos + hdr + size : (rel ? pos : 0) + blocks[blocks.Count - 1][1];
        if (enc != 0) encrypted++;
        else if (usize > (256L << 20)) skipped++;
        else {
          var data = new byte[usize]; bool ok = true;
          if (method == 0) { f.Seek(pos + hdr, SeekOrigin.Begin); ok = f.Read(data, 0, (int)usize) == usize; }
          else {
            long at = 0;
            foreach (var bl in blocks) {
              f.Seek((rel ? pos : 0) + bl[0], SeekOrigin.Begin); var comp = r.ReadBytes((int)(bl[1] - bl[0]));
              int want = (int)Math.Min(bs == 0 ? usize : bs, usize - at); var outb = new byte[want];
              if (method == 1) { using (var z = new DeflateStream(new MemoryStream(comp, 2, comp.Length - 2), CompressionMode.Decompress)) { int got = 0, k; while (got < want && (k = z.Read(outb, got, want - got)) > 0) got += k; ok &= got == want; } }
              else ok &= OodleLZ_Decompress(comp, comp.Length, outb, want, 1, 0, 0, IntPtr.Zero, 0, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, 0, 3) == want;
              if (!ok) break; Buffer.BlockCopy(outb, 0, data, (int)at, want); at += want;
            }
          }
          if (!ok) failed++;
          else {
            int n = (int)usize, c = Count(data, n, Dxbc);
            if (n >= 4 && data[0] == 0xC1 && data[1] == 0x83 && data[2] == 0x2A && data[3] == 0x9E) { packages++; zlibInPackages += Count(data, n, Zlib); }
            dxbc += c; if (c > 0) withDxbc++;
          }
        }
        if (next <= pos) { stop = string.Format("next entry {0} not after {1}", next, pos); break; }
        pos = next;
      }
    }
    sb.AppendFormat("{0}: {1} entries, {2:P0} of the data walked, stopped: {3}, {4:F0}s\n", Path.GetFileName(path), entries, pos / (double)Math.Max(1, new FileInfo(path).Length), stop, sw.Elapsed.TotalSeconds);
    sb.Append("  methods:"); foreach (var kv in methods) sb.AppendFormat(" 0x{0:x}={1}", kv.Key, kv.Value);
    sb.AppendFormat("\n  encrypted {0}, too big {1}, decompress failed {2}, packages {3}, zlib marks in packages {4}\n  DXBC: {5} containers in {6} files\n {7}\n", encrypted, skipped, failed, packages, zlibInPackages, dxbc, withDxbc, first);
    return sb.ToString();
  }
}
'@
if (-not ("PakWalk" -as [type])) { Add-Type -TypeDefinition ($src -replace 'oodle-not-used', $oodle) }
foreach ($n in $Names) {
    $p = Join-Path $Paks $n
    if (Test-Path $p) { [PakWalk]::Walk($p, $Seconds) } else { "$n : not found" }
}
