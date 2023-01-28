package com.rodrigo.userloginregistration.user;

import com.rodrigo.userloginregistration.registration.token.ConfirmationToken;
import com.rodrigo.userloginregistration.registration.token.ConfirmationTokenService;
import lombok.Data;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.UUID;

@Service
@Data
public class AppUserService implements UserDetailsService {

    private final AppUserRepo appUserRepo;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;
    private final ConfirmationTokenService confirmationTokenService;


    @Override
    public UserDetails loadUserByUsername(String email)
        throws UsernameNotFoundException{
        return appUserRepo.findByEmail(email).orElseThrow(()->
                new UsernameNotFoundException("User '" + email + "' not found"));
    }

    public String signUpUser(AppUser appUser){
        boolean userExists = appUserRepo.findByEmail(appUser.getEmail()).isPresent();

        if(userExists){

            throw new IllegalStateException("The email is already taken");
        }

        String encodedPassword = bCryptPasswordEncoder.encode(appUser.getPassword());

        appUser.setPassword(encodedPassword);

        appUserRepo.save(appUser);

        String token = UUID.randomUUID().toString();

        ConfirmationToken confirmationToken = new ConfirmationToken(
                token,
                LocalDateTime.now(),
                LocalDateTime.now().plusMinutes(15),
                appUser
                );

        confirmationTokenService.saveConfirmationToken(confirmationToken);


        return token;
    }

    public int enableAppUser(String email) {
        return appUserRepo.enableAppUser(email);
    }
}
