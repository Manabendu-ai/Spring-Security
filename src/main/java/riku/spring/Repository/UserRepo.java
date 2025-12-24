package riku.spring.Repository;

import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.stereotype.Repository;
import riku.spring.Model.User;

@Repository
public interface UserRepo extends MongoRepository<User, Object> {
    User findByusername(String username);
}
