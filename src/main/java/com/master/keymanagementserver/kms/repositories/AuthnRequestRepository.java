package com.master.keymanagementserver.kms.repositories;

import com.master.keymanagementserver.kms.models.AuthnRequestModel;
import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;

import java.util.Date;

/**
 * provides the search queries for the AuthnRequestModel table
 */
@Repository
public interface AuthnRequestRepository extends CrudRepository<AuthnRequestModel, String> {
    @Override
    Iterable<AuthnRequestModel> findAll();

    AuthnRequestModel findAuthnRequestById(String id);

    Iterable<AuthnRequestModel> findAuthnRequestsByNotValidAfterIsBefore(Date date);
}
