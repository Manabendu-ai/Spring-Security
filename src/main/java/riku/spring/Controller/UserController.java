package riku.spring.Controller;

import lombok.Getter;
import lombok.Setter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import riku.spring.Model.User;
import riku.spring.Service.UserService;

@RestController
@RequestMapping("mk")
@Getter
@Setter
public class UserController {

    @Autowired
    private UserService service;

    @PostMapping("/signup")
    public User register(
            @RequestBody User user
    ){
        return service.save(user);
    }
}

