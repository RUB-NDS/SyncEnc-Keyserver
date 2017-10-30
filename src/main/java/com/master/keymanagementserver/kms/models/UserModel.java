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

    // each email address should be unique
    @Basic(optional = false)
    @NotNull
    @Column(unique = true)
    private String email;

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

    public UserModel(String email) {
        this.email = email;

        /*
            the default state is the SENDPUBKEY state
            this will be changed in the application, due to what is stored in the database
         */
        this.state = UserStates.SENDPUBKEY;
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

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
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
