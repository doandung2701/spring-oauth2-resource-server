package com.buidoandung.resourceserver.config;

import java.util.Enumeration;

import javax.servlet.http.HttpServletRequest;

import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.authentication.OAuth2AuthenticationDetails;
import org.springframework.security.oauth2.provider.authentication.TokenExtractor;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;

public class CustomTokenExtractor implements TokenExtractor{

	@Override
	public Authentication extract(HttpServletRequest request) {
		// TODO Auto-generated method stub
		Enumeration<String> headers=request.getHeaders("Authorization");
		while (headers.hasMoreElements()) {
			String value = (String) headers.nextElement();
			if((value.toLowerCase().startsWith(OAuth2AccessToken.BEARER_TYPE.toLowerCase()))) {
				String authHeaderValue=value.substring(OAuth2AccessToken.BEARER_TYPE.length()).trim();
				request.setAttribute(OAuth2AuthenticationDetails.ACCESS_TOKEN_TYPE,value.substring(0,OAuth2AccessToken.BEARER_TYPE.length()).trim());
				int commaIndex=authHeaderValue.indexOf(",");
				if(commaIndex>0) {
					authHeaderValue=authHeaderValue.substring(0, commaIndex);
				}
				return new PreAuthenticatedAuthenticationToken(authHeaderValue, "");
			}
		}
		return null;
	}

}
