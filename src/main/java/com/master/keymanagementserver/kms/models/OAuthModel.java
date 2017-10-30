package com.master.keymanagementserver.kms.models;

import com.master.keymanagementserver.kms.crypto.Randomness;
import org.joda.time.DateTime;

import java.util.Date;
import javax.persistence.Basic;
import javax.persistence.Column;
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
@Table(name = "user_token", indexes = {@Index(columnList = "notValidAfter")})
public class OAuthModel {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @NotNull
    @Basic(optional = false)
    @Column(unique = true)
    private String tokenId;

    @NotNull
    @Basic(optional = false)
    private String tokenType;

    @NotNull
    @Basic(optional = false)
    @Temporal(TemporalType.TIMESTAMP)
    private Date notValidBefore;
    @NotNull
    @Basic(optional = false)
    @Temporal(TemporalType.TIMESTAMP)
    private Date notValidAfter;

    @NotNull
    @Basic(optional = false)
    @OneToOne
    private UserModel userModel;

    protected OAuthModel() {
    }

    /**
     * if no other valid time is provided, it will be set to 5 minutes
     *
     * @param tokenType the type of the token (actual just "access")
     * @param userModel the userModel the token belongs to
     */
    public OAuthModel(String tokenType, UserModel userModel) {
        this(tokenType, userModel, 300);
    }

    public OAuthModel(String tokenType, UserModel userModel, Integer validTimeInSeconds) {
        DateTime dt = new DateTime();
        notValidBefore = dt.toDate();
        // makes the request valid for the provided time in seconds
        notValidAfter = dt.plusSeconds(validTimeInSeconds).toDate();

        // the token needs to be unguessable so the id will be generated randomly
        Randomness randomness = new Randomness();
        this.tokenId = randomness.generateTokenWithoutDate(userModel.getEmail(), 32);

        this.tokenType = tokenType;
        this.userModel = userModel;
    }

    public Long getId() {
        return id;
    }

    public String getTokenType() {
        return tokenType;
    }

    public DateTime getNotValidBefore() {
        return new DateTime(notValidBefore.getTime());
    }

    public DateTime getNotValidAfter() {
        return new DateTime(notValidAfter.getTime());
    }

    public UserModel getUserModel() {
        return userModel;
    }

    public String getTokenId() {
        return tokenId;
    }

}
