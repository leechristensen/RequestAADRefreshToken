using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;

namespace RequestAADSamlRefreshToken
{
    [StructLayout(LayoutKind.Sequential)]
    public class ProofOfPossessionCookieInfo
    {
        public string Name { get; set; }
        public string Data { get; set; }
        public uint Flags { get; set; }
        public string P3PHeader { get; set; }
    }

    public static class ProofOfPossessionCookieInfoManager
    {
        // All these are defined in the Win10 WDK
        [Guid("CDAECE56-4EDF-43DF-B113-88E4556FA1BB")]
        [ComImport]
        [InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
        internal interface IProofOfPossessionCookieInfoManager
        {
            int GetCookieInfoForUri(
                [MarshalAs(UnmanagedType.LPWStr)] string Uri,
                out uint cookieInfoCount,
                out IntPtr output
            );
        }

        [Guid("A9927F85-A304-4390-8B23-A75F1C668600")]
        [ComImport]
        private class WindowsTokenProvider
        {
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct UnsafeProofOfPossessionCookieInfo
        {
            public readonly IntPtr NameStr;
            public readonly IntPtr DataStr;
            public readonly uint Flags;
            public readonly IntPtr P3PHeaderStr;
        }

        public static IEnumerable<ProofOfPossessionCookieInfo> GetCookieInfoForUri(string uri)
        {
            var provider = (IProofOfPossessionCookieInfoManager)new WindowsTokenProvider();
            var res = provider.GetCookieInfoForUri(uri, out uint count, out var ptr);

            if (count <= 0)
                yield break;

            var offset = ptr;
            for (int i = 0; i < count; i++)
            {
                var info = (UnsafeProofOfPossessionCookieInfo)Marshal.PtrToStructure(offset, typeof(UnsafeProofOfPossessionCookieInfo));

                var name = Marshal.PtrToStringUni(info.NameStr);
                var data = Marshal.PtrToStringUni(info.DataStr);
                var flags = info.Flags;
                var p3pHeader = Marshal.PtrToStringUni(info.P3PHeaderStr);


                yield return new ProofOfPossessionCookieInfo()
                {
                    Name = name,
                    Data = data,
                    Flags = flags,
                    P3PHeader = p3pHeader
                };

                Marshal.FreeCoTaskMem(info.NameStr);
                Marshal.FreeCoTaskMem(info.DataStr);
                Marshal.FreeCoTaskMem(info.P3PHeaderStr);

                offset = (IntPtr)(offset.ToInt64() + Marshal.SizeOf(typeof(ProofOfPossessionCookieInfo)));
            }

            Marshal.FreeCoTaskMem(ptr);
        }
    }


    class Program
    {
        static void Main(string[] args)
        {
            try
            {
                // This will likely always be the URL.
                // BrowserCore specifically looks in SOFTWARE\Microsoft\IdentityStore\LoadParameters\{B16898C6-A148-4967-9171-64D755DA8520} ! IDStoreLoadParametersAad
                // and SOFTWARE\Microsoft\Windows\CurrentVersion\AAD\Package ! LoginUri
                var uris = new[] { "https://login.microsoftonline.com/" };

                if (args.Length > 0)
                    uris = args;

                Console.WriteLine("Requesting cookies for the following URIs: " + String.Join(",", uris));
                Console.WriteLine($"PID  : {Process.GetCurrentProcess().Id}\n");

                foreach (var uri in uris)
                {
                    var cookies = ProofOfPossessionCookieInfoManager
                        .GetCookieInfoForUri(uri)
                        .ToList();

                    Console.WriteLine($"Uri: {uri}");

                    if (cookies.Any())
                    {
                        foreach (var c in cookies)
                        {
                            Console.WriteLine($"    Name      : {c.Name}");
                            Console.WriteLine($"    Flags     : {c.Flags}");
                            Console.WriteLine($"    Data      : {c.Data}");
                            Console.WriteLine($"    P3PHeader : {c.P3PHeader}\n");
                        }
                    }
                    else
                    {
                        Console.WriteLine($"    No cookies\n");
                    }
                }
            }
            catch (Exception e)
            {
                Console.WriteLine("Unhandled exception: " + e);
            }

            Console.WriteLine("DONE");
        }
    }
}