package com.master.keymanagementserver.kms.models;

import org.hibernate.annotations.GenericGenerator;
import org.joda.time.DateTime;

import java.util.Date;
import javax.persistence.Basic;
import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.Id;
import javax.persistence.Index;
import javax.persistence.Table;
import javax.persistence.Temporal;
import javax.persistence.TemporalType;
import javax.validation.constraints.NotNull;

@Entity
@Table(name = "authnRequest", indexes = {@Index(columnList = "notValidAfter")})
public class AuthnRequestModel {
    // The AuthnRequest needs an unique identifier
    @Id
    @GeneratedValue(generator = "uuid")
    @GenericGenerator(name = "uuid", strategy = "uuid2")
    private String id;

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
    @Column()
    private String relayState;

    @NotNull
    @Basic(optional = false)
    private String issuer;

    @NotNull
    @Basic(optional = false)
    private String username;

    protected AuthnRequestModel() {
    }

    /**
     * if no other valid time is provided, it will be set to 5 minutes
     *
     * @param relayState the relayState string which will be stored in the database
     * @param issuer     the issuer string which will be stored in the database
     */
    public AuthnRequestModel(String username, String relayState, String issuer) {
        this(username, relayState, issuer, 300);
    }

    public AuthnRequestModel(String username, String relayState, String issuer, Integer validTimeInSeconds) {
        DateTime dateTime = new DateTime();
        this.notValidBefore = dateTime.toDate();
        // makes the request valid for the provided time in seconds
        this.notValidAfter = dateTime.plusSeconds(validTimeInSeconds).toDate();

        this.relayState = relayState;
        this.issuer = issuer;
        this.username = username;
    }

    public String getId() {
        return id;
    }

    public DateTime getNotValidBefore() {
        return new DateTime(notValidBefore.getTime());
    }

    public DateTime getNotValidAfter() {
        return new DateTime(notValidAfter.getTime());
    }

    public String getRelayState() {
        return relayState;
    }

    public String getIssuer() {
        return issuer;
    }

    public String getUsername() {
        return username;
    }

}
