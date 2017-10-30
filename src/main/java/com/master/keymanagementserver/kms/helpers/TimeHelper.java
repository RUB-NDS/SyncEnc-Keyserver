package com.master.keymanagementserver.kms.helpers;

import org.joda.time.DateTime;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;

@Component
class TimeHelper {
    private static final Logger LOGGER = LoggerFactory.getLogger(TimeHelper.class.getName());

    @Autowired
    public TimeHelper() {

    }

    /**
     * check if the provided datetime is in the valid range
     *
     * @param testDateTime the date that has to be checked
     * @param object       the object that provides the notValidBefore and notValidAfter calls
     * @return false if datetime is before or after valid range, or datetime is after now, or now is after valid range
     * true otherwise
     */
    boolean checkTimeValidity(DateTime testDateTime, Object object) {
        if(LOGGER.isDebugEnabled()){
            LOGGER.debug("check the dateTime {}"
                    , LogEncoderHelper.encodeLogEntry(testDateTime.toString()));
        }
        Method getNotValidBeforeMethod;
        Method getNotValidAfterMethod;
        DateTime notValidBefore;
        DateTime notValidAfter;
        try {
            // need to get the two public methods and the DateTimes returned by the methods
            getNotValidBeforeMethod = object.getClass().getDeclaredMethod("getNotValidBefore");
            notValidBefore = (DateTime) getNotValidBeforeMethod.invoke(object);

            getNotValidAfterMethod = object.getClass().getDeclaredMethod("getNotValidAfter");
            notValidAfter = (DateTime) getNotValidAfterMethod.invoke(object);
        } catch (IllegalAccessException | InvocationTargetException | NoSuchMethodException e) {
            // if the object has no such method, return false
            LOGGER.error("{} has no method getNotValidBefore or getNotValidAfter. {}", object.getClass(), e);

            return false;
        }
        // if one of the DateTimes is null return false
        if (notValidAfter == null || notValidBefore == null) {
            LOGGER.error("can not get notValidAfter or notValidBefore");

            return false;
        }
        if(LOGGER.isDebugEnabled()){
            LOGGER.debug("should be in range {} - {}"
                    , LogEncoderHelper.encodeLogEntry(notValidBefore.toString())
                    , LogEncoderHelper.encodeLogEntry(notValidAfter.toString()));
        }

        // if testDateTime is after now it was created in the future so it is invalid
        if (testDateTime.isAfterNow()) {
            LOGGER.error("Is after now");

            return false;
        }

        // if now is after notValidAfter or before notValidBefore, than the valid range is expired
        if (!notValidAfter.isAfterNow() || !notValidBefore.isBeforeNow()) {
            LOGGER.error("now is not in valid range.");

            return false;
        }

        // if the testDateTime is after notValidAfter or before notValidBefore, than the valid range is expired
        if (!testDateTime.isBefore(notValidAfter) || !testDateTime.isAfter(notValidBefore)) {
            LOGGER.error("datetime to test is not in valid range.");

            return false;
        }

        if(LOGGER.isDebugEnabled()){
            LOGGER.debug("everything is valid.");
        }

        // otherwise everything is fine
        return true;
    }


}
