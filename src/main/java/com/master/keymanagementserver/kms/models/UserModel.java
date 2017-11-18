package com.master.keymanagementserver.kms.models;

import com.master.keymanagementserver.kms.helpers.UserStates;

import javax.persistence.Basic;
import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.EnumType;
import javax.persistence.Enumerated;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.Table;
import javax.validation.constraints.NotNull;

@Entity
@Table(name = "users")
public class UserModel {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Basic(optional = false)
    private Long id;

    // each username should be unique
    @Basic(optional = false)
    @NotNull
    @Column(unique = true)
    private String username;
    // each username should be unique
    @Basic(optional = false)
    @NotNull
    @Column(unique = true)
    private String stringIdIdP;
    @Column(length = 4096)
    private String publicKey;
    @Column(unique = true)
    private String keyNameIdentifier;
    private String salt;
    @Column(length = 8192)
    private String wrappedKey;
    @NotNull
    @Enumerated(EnumType.STRING)
    private UserStates state;
    protected UserModel() {
    }

    public UserModel(String username, String stringIdIdP) {
        this.username = username;
        this.stringIdIdP = stringIdIdP;

        /*
            the default state is the SENDPUBKEY state
            this will be changed in the application, due to what is stored in the database
         */
        this.state = UserStates.SENDPUBKEY;
    }

    public String getStringIdIdP() {
        return stringIdIdP;
    }

    public void setStringIdIdP(String stringIdIdP) {
        this.stringIdIdP = stringIdIdP;
    }

    public Long getId() {
        return id;
    }

    public String getKeyNameIdentifier() {
        return keyNameIdentifier;
    }

    public void setKeyNameIdentifier(String keyNameIdentifier) {
        this.keyNameIdentifier = keyNameIdentifier;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getWrappedKey() {
        return wrappedKey;
    }

    public void setWrappedKey(String wrappedKey) {
        this.wrappedKey = wrappedKey;
    }

    public String getPublicKey() {
        return publicKey;
    }

    public void setPublicKey(String publicKey) {
        this.publicKey = publicKey;
    }

    public String getSalt() {
        return salt;
    }

    public void setSalt(String salt) {
        this.salt = salt;
    }

    public UserStates getState() {
        return state;
    }

    public void setState(UserStates state) {
        this.state = state;
    }

}
