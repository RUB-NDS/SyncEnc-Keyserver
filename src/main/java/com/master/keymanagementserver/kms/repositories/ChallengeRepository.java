package com.master.keymanagementserver.kms.repositories;

import com.master.keymanagementserver.kms.models.ChallengeModel;
import com.master.keymanagementserver.kms.models.UserModel;
import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;

import java.util.Date;

/**
 * provides the search queries for the ChallengeModel table
 */
@Repository
public interface ChallengeRepository extends CrudRepository<ChallengeModel, Long> {
    @Override
    Iterable<ChallengeModel> findAll();

    ChallengeModel findChallengeByUserModel(UserModel userModel);

    Iterable<ChallengeModel> findChallengesByNotValidAfterBefore(Date date);
}
