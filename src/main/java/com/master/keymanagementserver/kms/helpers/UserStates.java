package com.master.keymanagementserver.kms.helpers;

public enum UserStates {
    SENDPUBKEY,
    SOLVECHALL,
    SENDWRAPPEDKEY,
    ACCESSWRAPPEDKEY;

    public String toString() {
        switch (this) {
            case SENDPUBKEY:
                return "SENDPUBKEY";
            case SOLVECHALL:
                return "SOLVECHALL";
            case SENDWRAPPEDKEY:
                return "SENDWRAPPEDKEY";
            case ACCESSWRAPPEDKEY:
                return "ACCESSWRAPPEDKEY";
        }
        return "SENDPUBKEY";
    }

}
