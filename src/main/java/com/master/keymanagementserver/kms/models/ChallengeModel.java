package com.master.keymanagementserver.kms.models;

import org.joda.time.DateTime;

import java.util.Date;
import javax.persistence.Basic;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.Index;
import javax.persistence.OneToOne;
import javax.persistence.Table;
import javax.persistence.Temporal;
import javax.persistence.TemporalType;
import javax.validation.constraints.NotNull;

@Entity
@Table(name = "user_challenges", indexes = {@Index(columnList = "notValidAfter")})
public class ChallengeModel {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @NotNull
    @Basic(optional = false)
    private String challenge;

    @NotNull
    @Basic(optional = false)
    @OneToOne
    private UserModel userModel;

    @NotNull
    @Basic(optional = false)
    @Temporal(TemporalType.TIMESTAMP)
    private Date notValidBefore;
    @NotNull
    @Basic(optional = false)
    @Temporal(TemporalType.TIMESTAMP)
    private Date notValidAfter;

    protected ChallengeModel() {

    }

    /**
     * if no other valid time is provided, it will be set to 5 minutes
     *
     * @param challenge the hashed challenge which will be stored in the database
     *                  , to check if the user solved it correctly
     * @param userModel the userModel the challenge belongs to
     */
    public ChallengeModel(String challenge, UserModel userModel) {
        this(challenge, userModel, 300);
    }

    public ChallengeModel(String challenge, UserModel userModel, Integer validTimeInSeconds) {
        DateTime dateTime = new DateTime();
        this.notValidBefore = dateTime.toDate();
        // makes the request valid for the provided time in seconds
        this.notValidAfter = dateTime.plusSeconds(validTimeInSeconds).toDate();

        this.challenge = challenge;
        this.userModel = userModel;
    }

    public DateTime getNotValidBefore() {
        return new DateTime(notValidBefore.getTime());
    }

    public DateTime getNotValidAfter() {
        return new DateTime(notValidAfter.getTime());
    }

    public Long getId() {
        return id;
    }

    public String getChallenge() {
        return challenge;
    }

    public UserModel getUserModel() {
        return userModel;
    }

}
