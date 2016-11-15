<%@ include file="/component/core/taglib/taglib.jsp"%>
<li><a href="#"><i class="fa fa-home"></i><span><fmt:message key="security.manager"></fmt:message></span></a>
	<ul class="sub-menu">
		<li class="<%=JspUtil.isActive(request, "/security/user")%>"><a href="<c:url value="/security/user/home"/>"><fmt:message key="security.user.manager"></fmt:message></a></li>
		<li class="<%=JspUtil.isActive(request, "/security/role")%>"><a href="<c:url value="/security/role/home"/>"><fmt:message key="security.role.manager"></fmt:message></a></li>
		<li class="<%=JspUtil.isActive(request, "/security/resource")%>"><a href="<c:url value="/security/resource/home"/>"><fmt:message key="security.resource.manager"></fmt:message></a></li>
		<li class="<%=JspUtil.isActive(request, "/security/menu")%>"><a href="/security/menu/home"><fmt:message key="security.menu.manager"></fmt:message></a></li>
		<li class="<%=JspUtil.isActive(request, "/sequence")%>"><a href="/sequence/home"><fmt:message key="global.sequence.manage"/></a></li>
	</ul></li>