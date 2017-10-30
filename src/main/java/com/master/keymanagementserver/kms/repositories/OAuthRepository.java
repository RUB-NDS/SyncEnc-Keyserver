package com.master.keymanagementserver.kms.repositories;

import com.master.keymanagementserver.kms.models.OAuthModel;
import com.master.keymanagementserver.kms.models.UserModel;
import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;

import java.util.Date;

/**
 * provides the search queries for the OAuthModel table
 */
@Repository
public interface OAuthRepository extends CrudRepository<OAuthModel, Long> {
    @Override
    Iterable<OAuthModel> findAll();

    OAuthModel findOAuthModelById(Long id);

    OAuthModel findOAuthModelByTokenId(String tokenId);

    OAuthModel findOAuthModelByUserModel(UserModel userModel);

    Iterable<OAuthModel> findOAuthModelsByNotValidAfterBefore(Date date);
}
