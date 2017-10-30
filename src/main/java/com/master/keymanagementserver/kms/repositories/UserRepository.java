package com.master.keymanagementserver.kms.repositories;

import com.master.keymanagementserver.kms.models.UserModel;
import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;

/**
 * provides the search queries for the UserModel table
 */
@Repository
public interface UserRepository extends CrudRepository<UserModel, Long> {
    UserModel findUserById(Long id);

    UserModel findUserByEmail(String email);

    UserModel findUserByKeyNameIdentifier(String keyNameIdentifier);

    @Override
    Iterable<UserModel> findAll();
}
