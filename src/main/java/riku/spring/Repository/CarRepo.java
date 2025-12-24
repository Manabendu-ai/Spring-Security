package riku.spring.Repository;

import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.stereotype.Repository;
import riku.spring.Model.Car;

import java.util.List;

@Repository
public interface CarRepo extends MongoRepository<Car, Object> {

    List<Car> findBycarId(int id);
}
