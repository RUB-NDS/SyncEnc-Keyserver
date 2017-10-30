package com.master.keymanagementserver.kms.helpers;

import com.master.keymanagementserver.kms.models.AuthnRequestModel;
import com.master.keymanagementserver.kms.models.ChallengeModel;
import com.master.keymanagementserver.kms.models.OAuthModel;
import com.master.keymanagementserver.kms.models.UserModel;
import org.joda.time.DateTime;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import java.util.concurrent.TimeUnit;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

/**
 * TimeHelper Tester.
 *
 * @author <Authors name>
 * @version 1.0
 * @since <pre>Oct 10, 2017</pre>
 */
public class TimeHelperTest {
    private UserModel userModel;
    private TimeHelper timeHelper;
    private ChallengeModel challengeModel;
    private OAuthModel oAuthModel;
    private AuthnRequestModel authnRequestModel;

    @Before
    public void before() throws Exception {
        timeHelper = new TimeHelper();
        userModel = new UserModel("pg@rub.de");
        challengeModel = new ChallengeModel("chall", userModel);
        oAuthModel = new OAuthModel("access", userModel);
        authnRequestModel = new AuthnRequestModel("relay", "issuer");
    }

    @After
    public void after() throws Exception {
    }

    /**
     * Method: checkTimeValidity(DateTime testDateTime, Object object)
     */
    @Test
    public void testCheckTimeValidityChallengeModel() throws Exception {
        TimeUnit.MILLISECONDS.sleep(1);
        assertTrue("", timeHelper.checkTimeValidity(DateTime.now(), challengeModel));
    }

    /**
     * Method: checkTimeValidity(DateTime testDateTime, Object object)
     * testDateTime is before valid range
     */
    @Test
    public void testCheckTimeValidityBeforeValidChallengeModel() throws Exception {
        DateTime now = DateTime.now();
        TimeUnit.SECONDS.sleep(2);
        ChallengeModel fastInvalid = new ChallengeModel("chall", userModel, 10);

        assertFalse("", timeHelper.checkTimeValidity(now, fastInvalid));
    }

    /**
     * Method: checkTimeValidity(DateTime testDateTime, Object object)
     * now is after valid range
     */
    @Test
    public void testCheckTimeValidityNowAfterValidChallengeModel() throws Exception {
        ChallengeModel fastInvalid = new ChallengeModel("chall", userModel, 1);
        TimeUnit.SECONDS.sleep(1);

        assertFalse("", timeHelper.checkTimeValidity(DateTime.now(), fastInvalid));
    }

    /**
     * Method: checkTimeValidity(DateTime testDateTime, Object object)
     * the testDateTime ist after now --> in case of creation time it is created after now
     */
    @Test
    public void testCheckTimeValidityAfterNowChallengeModel() throws Exception {
        assertFalse("", timeHelper.checkTimeValidity(DateTime.now().plusSeconds(20), challengeModel));
    }


    /**
     * Method: checkTimeValidity(DateTime testDateTime, Object object)
     */
    @Test
    public void testCheckTimeValidityOAuthModel() throws Exception {
        TimeUnit.MILLISECONDS.sleep(1);
        assertTrue("", timeHelper.checkTimeValidity(DateTime.now(), oAuthModel));
    }

    /**
     * Method: checkTimeValidity(DateTime testDateTime, Object object)
     * testDateTime is before valid range
     */
    @Test
    public void testCheckTimeValidityBeforeValidOAuthModel() throws Exception {
        DateTime now = DateTime.now();
        TimeUnit.SECONDS.sleep(1);
        OAuthModel fastInvalid = new OAuthModel("access", userModel, 10);

        assertFalse("", timeHelper.checkTimeValidity(now, fastInvalid));
    }

    /**
     * Method: checkTimeValidity(DateTime testDateTime, Object object)
     * now is after valid range
     */
    @Test
    public void testCheckTimeValidityNowAfterValidOAuthModel() throws Exception {
        OAuthModel fastInvalid = new OAuthModel("access", userModel, 1);
        TimeUnit.SECONDS.sleep(1);

        assertFalse("", timeHelper.checkTimeValidity(DateTime.now(), fastInvalid));
    }

    /**
     * Method: checkTimeValidity(DateTime testDateTime, Object object)
     * the testDateTime ist after now --> in case of creation time it is created after now
     */
    @Test
    public void testCheckTimeValidityAfterNowOAuthModel() throws Exception {
        assertFalse("", timeHelper.checkTimeValidity(DateTime.now().plusSeconds(20), challengeModel));
    }


    /**
     * Method: checkTimeValidity(DateTime testDateTime, Object object)
     */
    @Test
    public void testCheckTimeValidityAuthnRequestModel() throws Exception {
        TimeUnit.MILLISECONDS.sleep(2);
        assertTrue("", timeHelper.checkTimeValidity(DateTime.now(), authnRequestModel));
    }

    /**
     * Method: checkTimeValidity(DateTime testDateTime, Object object)
     * testDateTime is before valid range
     */
    @Test
    public void testCheckTimeValidityBeforeValidAuthnRequestModel() throws Exception {
        DateTime now = DateTime.now();
        TimeUnit.SECONDS.sleep(1);
        AuthnRequestModel fastInvalid = new AuthnRequestModel("relay", "issuer", 10);

        assertFalse("", timeHelper.checkTimeValidity(now, fastInvalid));
    }

    /**
     * Method: checkTimeValidity(DateTime testDateTime, Object object)
     * now is after valid range
     */
    @Test
    public void testCheckTimeValidityNowAfterValidAuthnRequestModel() throws Exception {
        AuthnRequestModel fastInvalid = new AuthnRequestModel("access", "issuer", 1);
        TimeUnit.SECONDS.sleep(1);

        assertFalse("", timeHelper.checkTimeValidity(DateTime.now(), fastInvalid));
    }

    /**
     * Method: checkTimeValidity(DateTime testDateTime, Object object)
     * the testDateTime ist after now --> in case of creation time it is created after now
     */
    @Test
    public void testCheckTimeValidityAfterNowAuthnRequestModel() throws Exception {
        assertFalse("", timeHelper.checkTimeValidity(DateTime.now().plusSeconds(20), authnRequestModel));
    }


}
