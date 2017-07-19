package com.faceye.component.security.service.impl;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;

import org.apache.commons.collections.CollectionUtils;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.access.SecurityConfig;
import org.springframework.security.web.FilterInvocation;
import org.springframework.security.web.access.intercept.FilterInvocationSecurityMetadataSource;
import org.springframework.stereotype.Service;
import org.springframework.util.AntPathMatcher;
import org.springframework.util.PathMatcher;

import com.faceye.component.security.entity.Resource;
import com.faceye.component.security.entity.Role;
import com.faceye.component.security.repository.mongo.ResourceRepository;
import com.faceye.component.security.service.ResourceService;
import com.faceye.component.security.service.RoleService;
import com.faceye.feature.service.impl.BaseMongoServiceImpl;

@Service("security-resourceService")
public class ResourceServiceImpl extends BaseMongoServiceImpl<Resource, Long, ResourceRepository>
		implements ResourceService, FilterInvocationSecurityMetadataSource {
	private PathMatcher pathMatcher = new AntPathMatcher();
	@Autowired
	private RoleService roleService = null;

	// 权限判断URL集合
	private List<Resource> resources = null;
	// 上一次刷新resourcs集合的时间
	private static Long LAST_REFRESH_RESOURCE_TIMESTAMP = 0L;
	// 缓存有效时间,5分趾
	private static Long CACHE_RESOURCE_EXPIRE_TIME_SECONDS = 5 * 60 * 1000L;

	private List<String> ignoreUrls = null;

	@Autowired
	public ResourceServiceImpl(ResourceRepository dao) {
		super(dao);
	}

	@Override

	public void remove(Long id) {
		Resource resource = this.get(id);
		List<Role> roles = this.roleService.getAll();
		if (CollectionUtils.isNotEmpty(roles)) {
			for (Role role : roles) {
				List<Resource> resources = role.getResources();
				if (CollectionUtils.isNotEmpty(resources)) {
					for (Resource r : resources) {
						if (r != null) {
							if (r.getId().compareTo(resource.getId()) == 0) {
								resources.remove(r);
							}
						}
					}
				}
				role.setResources(resources);
				this.roleService.save(role);
			}
		}
		this.dao.delete(resource);
	}

	@Override
	public void remove(Resource entity) {
		this.remove(entity.getId());
		;
	}

	@Override
	public Collection<ConfigAttribute> getAttributes(Object object) throws IllegalArgumentException {
		String url = ((FilterInvocation) object).getRequestUrl();
		if(this.isUrlIgnore(url)){
			return null;
		}
		logger.debug(">>FaceYe -->Security-->,filter url is:" + url);
		if (CollectionUtils.isEmpty(resources)
				|| System.currentTimeMillis() - LAST_REFRESH_RESOURCE_TIMESTAMP > CACHE_RESOURCE_EXPIRE_TIME_SECONDS) {
			resources = this.dao.findAll();
		}
		if (CollectionUtils.isNotEmpty(resources)) {
			
			for (Resource r : resources) {
				String _url = r.getUrl();
				if (StringUtils.isNotEmpty(_url) && !_url.endsWith("\\*")) {
					_url += "**";
				}
				if (pathMatcher.match(_url, url)) {
					// return r.getAttributes();
					return this.getAttributes(r);
				}
			}
		}
		return null;
	}

	/**
	 * 取得访问某一资源需要的角色
	 * 
	 * @todo
	 * @param resource
	 * @return
	 * @author:@haipenge haipenge@gmail.com 2015年3月14日
	 */
	private Collection<ConfigAttribute> getAttributes(Resource resource) {
		Collection<ConfigAttribute> attributes = new HashSet<ConfigAttribute>();
		List<Role> roles = this.roleService.getAll();
		if (CollectionUtils.isNotEmpty(roles)) {
			for (Role role : roles) {
				List<Resource> resources = role.getResources();
				for (Resource r : resources) {
					if (r.getId().compareTo(resource.getId()) == 0) {
						ConfigAttribute ca = new SecurityConfig(role.getRoleAuth());
						attributes.add(ca);
					}
				}
			}
		}
		return attributes;
	}

	// public Collection<ConfigAttribute> getAttributes() {
	// Collection<ConfigAttribute> attributes = new HashSet<ConfigAttribute>();
	// if (null != this.getRoles()) {
	// Iterator it = this.getRoles().iterator();
	// while (it.hasNext()) {
	// Role role = (Role) it.next();
	// ConfigAttribute ca = new SecurityConfig(role.getRoleAuth());
	// attributes.add(ca);
	// }
	// }
	// return attributes;
	// }

	@Override
	public Collection<ConfigAttribute> getAllConfigAttributes() {
		Collection<ConfigAttribute> allAttributes = null;
		allAttributes = this.roleService.getAllConfigAttributes();
		return allAttributes;
	}

	@Override
	public boolean supports(Class<?> clazz) {
		return true;
	}

	@Override
	public Resource getResourceByUrl(String url) {
		return this.dao.getResourceByUrl(url);
	}

	@Override
	public Resource getResourceByMenuId(Long menuId) {
		return this.dao.getResourceByMenuId(menuId);
	}
	
	/**
	 * 是否忽略的URL权限限制
	 * 
	 * @param url
	 * @return
	 */
	private boolean isUrlIgnore(String url) {
		boolean res = false;
		List<String> ignoreUrls = this.ignoreUrls();
		for (String regexp : ignoreUrls) {
			res = pathMatcher.match(regexp, url);
			if (res) {
				break;
			}
		}
		return res;
	}

	private List<String> ignoreUrls() {
		if (CollectionUtils.isEmpty(ignoreUrls)) {
			ignoreUrls=new ArrayList<String>(0);
			ignoreUrls.add("/static/**");
			ignoreUrls.add("/public/**");
			ignoreUrls.add("/images/**");
			ignoreUrls.add("/js/**");
			ignoreUrls.add("/css/**");
			ignoreUrls.add("*.js");
			ignoreUrls.add("*.css");
			ignoreUrls.add("*.jpg");
			ignoreUrls.add("*.png");
			ignoreUrls.add("*.gif");
			ignoreUrls.add("favor.ico");
		}
		return ignoreUrls;
	}

}
/** @generate-service-source@ **/
