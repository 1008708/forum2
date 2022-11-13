package telran.java2022.security.filter;

import java.io.IOException;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

import lombok.RequiredArgsConstructor;
import telran.java2022.accounting.dao.UserAccountRepository;
import telran.java2022.accounting.model.UserAccount;

@Component
@Order(30)
@RequiredArgsConstructor
public class UserPutDeleteFilter implements Filter {

	final UserAccountRepository userAccountRepository;

	@Override
	public void doFilter(ServletRequest req, ServletResponse resp, FilterChain chain)
			throws IOException, ServletException {
		HttpServletRequest request = (HttpServletRequest) req;
		HttpServletResponse response = (HttpServletResponse) resp;
		String path = request.getServletPath();
		
		if (checkEndPoint(path) && "DELETE".equals(request.getMethod())) {
			UserAccount userAccount = userAccountRepository.findById(request.getUserPrincipal().getName()).get();
			String userString = ".+/"+userAccount.getLogin()+"/?";
			if (!path.matches(userString) && !userAccount.getRoles().contains("Administrator".toUpperCase())) {
				response.sendError(403);
				return;
				}
		}

		if (checkEndPoint(path) && "PUT".equals(request.getMethod())) {
			UserAccount userAccount = userAccountRepository.findById(request.getUserPrincipal().getName()).get();
			String userString = ".+/"+userAccount.getLogin()+"/?";
			if (!path.matches(userString)) {
				response.sendError(403);
				return;
				}
		}
		chain.doFilter(request, response);
	}

	private boolean checkEndPoint(String servletPath) {
		return servletPath.matches("/account/user/\\w+/?");
	}
}