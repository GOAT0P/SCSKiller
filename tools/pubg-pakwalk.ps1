# Throwaway diagnostic for PUBG (not for upstream): walks a pak's entries from byte 0 without its encrypted index,
# decompresses them with the Oodle DLL SCSKiller's build downloaded, and counts what is inside. Reads files only.
param([switch]$Encrypted, [switch]$Scan, [switch]$All, [string]$Paks = "C:\Program Files (x86)\Steam\steamapps\common\PUBG\TslGame\Content\Paks", [int]$Seconds = 60,
      [string[]]$Names = @("pakchunk0-WindowsNoEditor.pak", "pakchunk0-WindowsNoEditor_etc.pak", "pakchunk0-WindowsNoEditor_fx.pak",
                           "pakchunk0-WindowsNoEditor_bps.pak", "pakchunk0-WindowsNoEditor_assets_world.pak", "pakchunk0-WindowsNoEditor_mutable.pak"))
$oodle = Join-Path $env:LOCALAPPDATA "SCSKiller-build\codecs\oodle-data-shared.dll"
if (-not (Test-Path $oodle)) { throw "no $oodle : run build\publish.ps1 once first" }
$src = @'
using System; using System.IO; using System.IO.Compression; using System.Runtime.InteropServices; using System.Collections.Generic; using System.Diagnostics; using System.Text;
public static class PakWalk {
  [DllImport(@"oodle-not-used")] static extern long OodleLZ_Decompress(byte[] src, long srcLen, byte[] dst, long dstLen, int fuzz, int crc, int verb, IntPtr a, long b, IntPtr c, IntPtr d, IntPtr e, long f, int g);
  static int Count(byte[] b, int n, byte[] pat) {
    int c = 0, i = 0;
    while (i + pat.Length <= n) {
      int j = Array.IndexOf(b, pat[0], i, n - pat.Length + 1 - i); if (j < 0) break;
      int k = 1; while (k < pat.Length && b[j + k] == pat[k]) k++;
      if (k == pat.Length) c++; i = j + 1;
    }
    return c;
  }
  static readonly byte[] BasePass = Encoding.ASCII.GetBytes("BasePassPS"), GlobalCache = Encoding.ASCII.GetBytes("GlobalShaderCache"),
    ShaderCode = Encoding.ASCII.GetBytes("ShaderCode"), ShaderArchive = Encoding.ASCII.GetBytes("ShaderArchive");
  static readonly byte[] Dxbc = Encoding.ASCII.GetBytes("DXBC"), Tag = { 0xC1, 0x83, 0x2A, 0x9E }, Zlib = { 0x78, 0x9C };
  sealed class Entry { public long Hdr, Size, USize, Next; public int Method, Enc; public uint Bs; public List<long[]> Blocks = new List<long[]>(); }
  // An in-data FPakEntry (v4: absolute block offsets) at p that is really one: offset field 0, sizes that fit, compressed
  // blocks contiguous from right after the header, a stored file whose SHA-1 is the header's hash. Null when not.
  static Entry Read(FileStream f, BinaryReader r, long p, long dataEnd) {
    if (p + 53 > dataEnd) return null;
    f.Seek(p, SeekOrigin.Begin);
    var e = new Entry(); long off = r.ReadInt64(); e.Size = r.ReadInt64(); e.USize = r.ReadInt64(); e.Method = r.ReadInt32(); var hash = r.ReadBytes(20);
    if (off != 0 || e.Size <= 0 || e.USize <= 0 || e.USize > (1L << 32) || e.Method < 0 || e.Method > 0x100) return null;
    if (e.Method != 0) {
      int n = r.ReadInt32(); if (n < 1 || n > 65536 || p + 53 + 4 + 16L * n > dataEnd) return null;
      for (int i = 0; i < n; i++) e.Blocks.Add(new[] { r.ReadInt64(), r.ReadInt64() });
    }
    e.Enc = r.ReadByte(); e.Bs = r.ReadUInt32(); e.Hdr = f.Position - p;
    if (e.Enc > 1) return null;
    if (e.Method == 0) {
      if (e.Size != e.USize || p + e.Hdr + e.Size > dataEnd) return null;
      e.Next = p + e.Hdr + e.Size;
      if (e.Size <= (64 << 20)) { var data = r.ReadBytes((int)e.Size); using (var sha = System.Security.Cryptography.SHA1.Create()) { var h = sha.ComputeHash(data); for (int i = 0; i < 20; i++) if (h[i] != hash[i]) return null; } }
      return e;
    }
    long at = p + e.Hdr;
    foreach (var b in e.Blocks) { if (b[0] != at || b[1] <= b[0] || b[1] > dataEnd) return null; at = b[1]; }
    if (at - (p + e.Hdr) != e.Size) return null;
    e.Next = at;
    return e;
  }
  public static string Walk(string path, int maxSec) { return Walk(path, maxSec, false); }
  public static string Walk(string path, int maxSec, bool headersOnly) {
    var encList = new List<string>(); long encBytes = 0;
    var sw = Stopwatch.StartNew(); var sb = new StringBuilder(); var methods = new SortedDictionary<int, int>();
    long entries = 0, encrypted = 0, failed = 0, packages = 0, dxbc = 0, withDxbc = 0, zlibInPackages = 0, skipped = 0, pos = 0;
    long basePass = 0, basePassFiles = 0, globalCache = 0, shaderCode = 0, biggest = 0; string biggestAt = ""; long gaps = 0, gapBytes = 0, maxGap = 0, at2k = 0, at4k = 0, at64k = 0;
    string stop = "end of data";
    using (var f = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete)) {
      var r = new BinaryReader(f);
      f.Seek(-45, SeekOrigin.End); var fb = r.ReadBytes(45);
      if (BitConverter.ToUInt32(fb, 1) != 0x5A6F12E1) return Path.GetFileName(path) + ": no v4 footer";
      long dataEnd = BitConverter.ToInt64(fb, 9);
      while (pos < dataEnd) {
        if (sw.Elapsed.TotalSeconds > maxSec) { stop = "time limit"; break; }
        var e = Read(f, r, pos, dataEnd);
        if (e == null) {  // padding: the next header within 1 MB (its offset field is 8 zero bytes)
          long limit = Math.Min(dataEnd, pos + (1 << 20)), found = -1;
          var win = new byte[(int)(limit - pos)]; f.Seek(pos, SeekOrigin.Begin); int got = f.Read(win, 0, win.Length);
          for (int pass = 0; pass < 2 && found < 0; pass++)
            for (int i = pass == 0 ? (int)(2048 - pos % 2048) % 2048 : 1; i + 8 <= got && found < 0; i += pass == 0 ? 2048 : 1)
              if (i > 0 && (pass == 0 || (pos + i) % 2048 != 0) && BitConverter.ToInt64(win, i) == 0 && (e = Read(f, r, pos + i, dataEnd)) != null) found = pos + i;
          if (found < 0) { stop = string.Format("lost track at {0}: no entry within 1 MB", pos); break; }
          gaps++; gapBytes += found - pos; maxGap = Math.Max(maxGap, found - pos);
          if (found % 2048 == 0) at2k++; if (found % 4096 == 0) at4k++; if (found % 65536 == 0) at64k++;
          pos = found;
        }
        entries++; int m; methods[e.Method] = methods.TryGetValue(e.Method, out m) ? m + 1 : 1;
        if (e.Enc != 0) { encrypted++; encBytes += e.Size; if (encList.Count < 10) encList.Add(string.Format("{0:N0} B (stored {1:N0}, method 0x{2:x}) at {3}", e.USize, e.Size, e.Method, pos)); }
        else if (headersOnly) { }
        else if (e.USize > (256L << 20)) skipped++;
        else {
          var data = new byte[e.USize]; bool ok = true;
          if (e.Method == 0) { f.Seek(pos + e.Hdr, SeekOrigin.Begin); ok = f.Read(data, 0, (int)e.USize) == e.USize; }
          else {
            long at = 0;
            foreach (var bl in e.Blocks) {
              f.Seek(bl[0], SeekOrigin.Begin); var comp = r.ReadBytes((int)(bl[1] - bl[0]));
              int want = (int)Math.Min(e.Bs == 0 ? e.USize : e.Bs, e.USize - at); var outb = new byte[want];
              if (e.Method == 1) { using (var z = new DeflateStream(new MemoryStream(comp, 2, comp.Length - 2), CompressionMode.Decompress)) { int got = 0, k; while (got < want && (k = z.Read(outb, got, want - got)) > 0) got += k; ok &= got == want; } }
              else ok &= OodleLZ_Decompress(comp, comp.Length, outb, want, 1, 0, 0, IntPtr.Zero, 0, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, 0, 3) == want;
              if (!ok) break; Buffer.BlockCopy(outb, 0, data, (int)at, want); at += want;
            }
          }
          if (!ok) failed++;
          else {
            int n = (int)e.USize, c = Count(data, n, Dxbc);
            if (n >= 4 && data[0] == 0xC1 && data[1] == 0x83 && data[2] == 0x2A && data[3] == 0x9E) { packages++; zlibInPackages += Count(data, n, Zlib); }
            dxbc += c; if (c > 0) withDxbc++;
            int bp = Count(data, n, BasePass); basePass += bp; if (bp > 0) { basePassFiles++; if (n > biggest) { biggest = n; biggestAt = string.Format("{0:N0} B at {1}{2}", n, pos, data[0] == 0xC1 && data[1] == 0x83 ? " (package)" : ""); } }
            globalCache += Count(data, n, GlobalCache); shaderCode += Count(data, n, ShaderCode) + Count(data, n, ShaderArchive);
          }
        }
        pos = e.Next;
      }
    }
    sb.AppendFormat("{0}: {1} entries, {2:P1} of the file walked, stopped: {3}, {4:F0}s\n", Path.GetFileName(path), entries, pos / (double)Math.Max(1, new FileInfo(path).Length), stop, sw.Elapsed.TotalSeconds);
    sb.Append("  methods:"); foreach (var kv in methods) sb.AppendFormat(" 0x{0:x}={1}", kv.Key, kv.Value);
    sb.AppendFormat("\n  padding: {0} gaps, {1} bytes, largest {2}; next entry on 2K {3}, 4K {4}, 64K {5}\n", gaps, gapBytes, maxGap, at2k, at4k, at64k);
    if (encrypted > 0) { sb.AppendFormat("  ENCRYPTED: {0} files, {1:N0} bytes stored\n", encrypted, encBytes); foreach (var x in encList) sb.Append("    " + x + "\n"); }
    if (headersOnly) return sb.ToString();
    sb.AppendFormat("  encrypted {0}, too big {1}, decompress failed {2}, packages {3}, zlib marks in packages {4}\n  DXBC: {5} containers in {6} files\n", encrypted, skipped, failed, packages, zlibInPackages, dxbc, withDxbc);
    sb.AppendFormat("  BasePassPS: {0} in {1} files (largest {2}); GlobalShaderCache: {3}; ShaderCode/ShaderArchive: {4}\n", basePass, basePassFiles, biggestAt, globalCache, shaderCode);
    return sb.ToString();
  }
}
'@
if (-not ("PakWalk" -as [type])) { Add-Type -TypeDefinition ($src -replace 'oodle-not-used', $oodle) }
if ($Encrypted) {  # every pak, headers only: which files are encrypted, and how big
    $list = @(Get-ChildItem $Paks -Filter *.pak | Sort-Object Name); $i = 0
    foreach ($p in $list) {
        $i++; Write-Progress -Activity "Walking pak headers" -Status $p.Name -PercentComplete (100 * $i / $list.Count)
        $out = [PakWalk]::Walk($p.FullName, $Seconds, $true)
        if ($out -match 'ENCRYPTED|lost track|no v4 footer') { $out }
    }
    "$($list.Count) paks walked"
    return
}
if ($Scan) {  # every pak but textures, sound, localization and animations, decompressed: where the shaders are; -All: only those
    $left = '_tex|_sound|_localize|_animations'
    $list = @(Get-ChildItem $Paks -Filter *.pak | Where-Object { if ($All) { $_.Name -match $left } else { $_.Name -notmatch $left } } | Sort-Object Length)
    $i = 0; $sw = [Diagnostics.Stopwatch]::StartNew()
    foreach ($p in $list) {
        $i++; Write-Progress -Activity "Scanning paks ($i of $($list.Count), $([int]$sw.Elapsed.TotalMinutes) min)" -Status $p.Name -PercentComplete (100 * $i / $list.Count)
        $out = [PakWalk]::Walk($p.FullName, 600)
        if ($out -match 'DXBC: [1-9]|BasePassPS: [1-9]|GlobalShaderCache: [1-9]|ShaderArchive: [1-9]|lost track|time limit|decompress failed [1-9]') { $out }
    }
    "$($list.Count) paks scanned in $([int]$sw.Elapsed.TotalMinutes) min"
    return
}
foreach ($n in $Names) {
    $p = Join-Path $Paks $n
    if (Test-Path $p) { [PakWalk]::Walk($p, $Seconds) } else { "$n : not found" }
}
