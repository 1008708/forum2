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
import org.springframework.web.bind.annotation.RequestMapping;

import lombok.RequiredArgsConstructor;
import telran.java2022.accounting.dao.UserAccountRepository;
import telran.java2022.accounting.model.UserAccount;
import telran.java2022.post.dao.PostRepository;
import telran.java2022.post.model.Post;

@Component
@Order(40)
@RequiredArgsConstructor
public class PostFilter implements Filter {

	final UserAccountRepository userAccountRepository;
	final PostRepository postRepository;

	@Override
	public void doFilter(ServletRequest req, ServletResponse resp, FilterChain chain)
			throws IOException, ServletException {
		HttpServletRequest request = (HttpServletRequest) req;
		HttpServletResponse response = (HttpServletResponse) resp;
		String path = request.getServletPath();

		if (checkEndPoint(path)) {
			UserAccount userAccount = userAccountRepository.findById(request.getUserPrincipal().getName()).get();
			if ("POST".equals(request.getMethod())) {
				if (!path.matches(".+post/" + userAccount.getLogin() + "/?")) {
					response.sendError(403);
					return;
				}
			}
			if ("DELETE".equals(request.getMethod())
					&& !userAccount.getRoles().contains("MODERATOR")) {
				String id = path.substring(path.lastIndexOf("post/") + 5);
				Post post = postRepository.findById(id).orElse(null);
				if (post != null && !post.getAuthor().equals(userAccount.getLogin())) {
					response.sendError(403);
					return;
				}
			}
			
			if ("PUT".equals(request.getMethod()) && !path.contains("comment")) {
					String id = path.substring(path.lastIndexOf("post/") + 5);
					Post post = postRepository.findById(id).orElse(null);
					if (post != null && !post.getAuthor().equals(userAccount.getLogin())) {
						response.sendError(403);
						return;
					}
				} 
			if ("PUT".equals(request.getMethod()) && path.contains("comment") && (!path.matches(".+/" + userAccount.getLogin() + "/?"))) {
					response.sendError(403);
					return;
			}
		}
		chain.doFilter(request, response);
	}
	
	@RequestMapping
	private boolean checkEndPoint(String servletPath) {
		return servletPath.matches("/forum/post/.+/?");
	}

}
