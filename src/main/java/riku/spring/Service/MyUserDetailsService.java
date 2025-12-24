package riku.spring.Service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;
import riku.spring.Model.User;
import riku.spring.Model.UserPrincipal;
import riku.spring.Repository.UserRepo;
@Component
public class MyUserDetailsService implements UserDetailsService {

    @Autowired
    private UserRepo repo;
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = repo.findByusername(username);
        if(user == null){
            System.out.println("USER Not Found!");
            throw new UsernameNotFoundException("User 404");
        }

        return new UserPrincipal(user);
    }
}
