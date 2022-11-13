package telran.java2022.security.filter;

import java.io.IOException;
import java.security.Principal;
import java.util.Base64;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;
import javax.servlet.http.HttpServletResponse;

import org.mindrot.jbcrypt.BCrypt;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

import lombok.RequiredArgsConstructor;
import telran.java2022.accounting.dao.UserAccountRepository;
import telran.java2022.accounting.model.UserAccount;

@Component
@Order(10)
@RequiredArgsConstructor
public class AuthenticationFilter implements Filter {
	
	final UserAccountRepository userAccountRepository;

	@Override
	public void doFilter(ServletRequest req, ServletResponse resp, FilterChain chain)
			throws IOException, ServletException {
		HttpServletRequest request = (HttpServletRequest) req;
		HttpServletResponse response = (HttpServletResponse) resp;
		if (checkEndPoint(request.getMethod(), request.getServletPath())) {
			String token = request.getHeader("Authorization");
			if(token == null) {
				response.sendError(401);
				return;
			}
			
			String[] credentials;
			try {
				credentials = getCredentialsFromToken(token);
			} catch (Exception e) {
				response.sendError(401, "Invalid token");
				return;
			}
			
			UserAccount userAccount = userAccountRepository.findById(credentials[0]).orElse(null);
			if(userAccount == null || !BCrypt.checkpw(credentials[1], userAccount.getPassword())) {
				response.sendError(401, "login or password is invalid");
				return;
			}
			request = new WrapperRequest(request, userAccount.getLogin());
			
		}
		chain.doFilter(request, response);
	}

	private String[] getCredentialsFromToken(String token) {
		String[] basicAuth = token.split(" ");
		String decode = new String(Base64.getDecoder().decode(basicAuth[1]));
		String[] credentials = decode.split(":");
		return credentials;
	}

	private boolean checkEndPoint(String method, String servletPath) {
		boolean flag1 = "POST".equalsIgnoreCase(method) && servletPath.matches("/account/register/?");
		boolean flag2 = ("POST".equalsIgnoreCase(method) || "GET".equalsIgnoreCase(method))	&& servletPath.matches("/forum/posts/.+"); 
		return !flag1 && !flag2;
	}

	private class WrapperRequest extends HttpServletRequestWrapper {
		String login;
		public WrapperRequest(HttpServletRequest request, String login) {
			super(request);
			this.login = login;
		}
		
		@Override
		public Principal getUserPrincipal() {
			return () -> login; 
		}
	}
}
