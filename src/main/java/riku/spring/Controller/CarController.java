package riku.spring.Controller;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.Getter;
import lombok.Setter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.web.bind.annotation.*;
import riku.spring.Model.Car;
import riku.spring.Repository.CarRepo;

import java.util.List;

@RestController
@RequestMapping("/mk")
@Getter
@Setter
public class CarController {

    @Autowired
    private CarRepo repo;

    @GetMapping("/cars")
    public List<Car> getAllCars(){
        return repo.findAll();
    }

    @GetMapping("/token")
    public CsrfToken getCsrfToken(HttpServletRequest req){
        return (CsrfToken) req.getAttribute("_csrf");
    }

    @GetMapping("/sessionId")
    public String getSessionId(HttpServletRequest req){
        return req.getSession().getId();
    }
    @GetMapping("/cars/{carId}")
    public Car getCarbyId(
            @PathVariable("carId") int carId
    ){
        List<Car> car = repo.findBycarId(carId);
        if(!(car==null)){
            return car.getFirst();
        }
        return null;
    }

    @PostMapping("/cars")
    public Car postCars(
            @RequestBody Car car
    ){
        repo.save(car);
        return car;
    }

    @PutMapping("/cars")
    public Car putCars(
            @RequestBody Car car
    ){
        repo.save(car);
        return car;
    }

    @DeleteMapping("/cars/{id}")
    public Car deleteCars(
            @PathVariable int id
    ){
        List<Car> car = repo.findBycarId(id);
        if(car!=null) {
            repo.deleteById(car.getFirst().getId());
            return car.getFirst();
        }
        return null;
    }
}
