package org.forgerock.openam.auth.nodes.marketplace.SecurID;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.ResourceBundle;
import java.util.UUID;

import javax.inject.Inject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.ChoiceCallback;
import javax.security.auth.callback.ConfirmationCallback;

import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.conn.ssl.NoopHostnameVerifier;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;
import org.forgerock.json.JsonValue;
import org.forgerock.openam.annotations.sm.Attribute;
import org.forgerock.openam.auth.node.api.AbstractDecisionNode;
import org.forgerock.openam.auth.node.api.Action;
import org.forgerock.openam.auth.node.api.Node;
import org.forgerock.openam.auth.node.api.NodeProcessException;
import org.forgerock.openam.auth.node.api.NodeState;
import org.forgerock.openam.auth.node.api.TreeContext;
import org.forgerock.openam.sm.annotations.adapters.Password;
import org.forgerock.openam.utils.StringUtils;
import org.forgerock.util.i18n.PreferredLocales;
import org.json.JSONArray;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.collect.ImmutableList;
import com.google.inject.assistedinject.Assisted;
import com.sun.identity.sm.RequiredValueValidator;

import static com.daon.idxAuthRequestNode.DaonSaasOnboardingConstants.OIDC_CODE;

/**
 * A node that checks to see if zero-page login headers have specified username
 * and whether that username is in a group permitted to use zero-page login
 * headers.
 */
@Node.Metadata(outcomeProvider = SecurID.SecurIDOutcomeProvider.class, configClass = SecurID.Config.class, tags = {
        "marketplace", "trustnetwork" })
public class SecurID extends AbstractDecisionNode {

    private final Logger logger = LoggerFactory.getLogger(SecurID.class);
    private String loggerPrefix = "[SecurID]" + SecurIDPlugin.logAppender;
    private static final String BUNDLE = SecurID.class.getName();
    private final Config config;
    private static final String SUCCESS = "SUCCESS";
    private static final String ERROR = "ERROR";
    private static final String FAILURE = "FAILURE";
    private static final String CHALLENGE = "CHALLENGE";
    private static final String NOTENROLLED = "NOTENROLLED";
    private static final String NOTSUPPORTED = "NOTSUPPORTED";
    private static final String CANCEL = "CANCEL";

    private static final String initializeAppend = "/authn/initialize";

    /**
     * Configuration for the node.
     */
    public interface Config {

        @Attribute(order = 100, validators = { RequiredValueValidator.class })
        default String baseURL() {
            return "https://yourtenant.securid.com/mfa/v1_1";
        }

        @Attribute(order = 200, validators = { RequiredValueValidator.class })
        String clientID();

        @Attribute(order = 300, validators = { RequiredValueValidator.class })
        String assurancePolicy();

        @Attribute(order = 400, validators = { RequiredValueValidator.class })
        @Password
        String clientKey();

        @Attribute(order = 500, validators = { RequiredValueValidator.class })
        default boolean verifySSL() {
            return false;
        }

        @Attribute(order = 600, validators = { RequiredValueValidator.class })
        default String thePrompt() {
            return "Select your preferred MFA";
        }
    }

    @Inject
    public SecurID(@Assisted Config config) {
        this.config = config;
    }

    @Override
    public Action process(TreeContext context) {
        try {
            if (!context.hasCallbacks()) {
//First time here.  Initialize and display choice.  Considered step 0
                List<Callback> callbacks = initialize(context);
                return Action.send(callbacks).build();
            }
            else {
//check if we just came from step 0, which indicates the user has selected there MFA path
//otherwise, we are already on a MFA path and either verifying or waiting for a push completion
                NodeState ns = context.getStateFor(this);
                switch(ns.get("P1ProtectStep").asInteger().intValue()){
                    case 0://they picked which MFA they want to use

                    case 1://they went with token or emergency token

                    case 2:

                    case 3:
                }


//Second time here.  Either choice picked, or other.  Will use shared state to determine which I'm on
                for(Iterator<? extends Callback> thisIt = context.getAllCallbacks().iterator();thisIt.hasNext();) {
                    Callback thisCallback = thisIt.next();
                    if (thisCallback instanceof ChoiceCallback) {
                        ChoiceCallback cb = (ChoiceCallback)thisCallback;
                        System.out.println("Selected index: " + cb.getSelectedIndexes()[0]);
                        System.out.println("Here's the choice: " + (cb.getChoices())[cb.getSelectedIndexes()[0]]);
                    }
                }

            }

        } catch (Exception ex) {
            String stackTrace = org.apache.commons.lang.exception.ExceptionUtils.getStackTrace(ex);
            logger.error(loggerPrefix + "Exception occurred: " + stackTrace);
            context.getStateFor(this).putTransient(loggerPrefix + "Exception", new Date() + ": " + ex.getMessage());
            context.getStateFor(this).putTransient(loggerPrefix + "StackTrace", new Date() + ": " + stackTrace);
            return Action.goTo(ERROR).withHeader("Error occurred").withErrorMessage(ex.getMessage()).build();
        }

        return Action.goTo(ERROR).build();
    }

    private List<Callback> initialize(TreeContext context) throws Exception{
        NodeState ns = context.getStateFor(this);
        String username = ns.get("username").asString();
        if (StringUtils.isEmpty(username)) {
            throw new NodeProcessException("username does not exist in sharedsate");
        }

        HttpPost post = new HttpPost(config.baseURL() + initializeAppend);
        JsonValue theBody = getInitializeBody(config.clientID(), username, config.assurancePolicy());
        post.setEntity(new StringEntity(theBody.toString()));

//Send init call to SecurID
        JSONObject fromPost = doPost(post);

//Parse choices from init call back from SecurID
        ArrayList<String> choices = getChoices(fromPost);

//Save things to TransientState
        ns.putTransient("inResponseTo", getDataFromContext(fromPost,"messageId"));
        ns.putTransient("authnAttemptId", getDataFromContext(fromPost,"authnAttemptId"));
        ns.putTransient("P1ProtectStep", 0);

//Then send to screen options
        ChoiceCallback cc = new ChoiceCallback(config.thePrompt(),Arrays.copyOf(choices.toArray(),choices.size(),String[].class), 0,false);
        ConfirmationCallback confirmationCallback = new ConfirmationCallback(ConfirmationCallback.INFORMATION, new String[]{"Next", "Cancel"}, 0);

        List<Callback> callbacks = new ArrayList<>();
        callbacks.add(cc);
        callbacks.add(confirmationCallback);
        return callbacks;

    }


    private JsonValue getInitializeBody(String clientID, String subject, String assurance) {

        JsonValue body = new JsonValue(new LinkedHashMap<String, Object>(1));

        body.put("authnAttemptTimeout", 180);
        body.put("clientId", clientID);
        body.put("subjectName", subject);
        body.put("lang", "us_EN");
        body.put("assurancePolicyId", assurance);

        JsonValue contextBody = new JsonValue(new LinkedHashMap<String, Object>(1));
        contextBody.put("messageId", UUID.randomUUID().toString());

        body.put("context", contextBody);

        return body;

    }

    private JsonValue getContext(JSONObject fromPost) {
        JsonValue contextBody = new JsonValue(new LinkedHashMap<String, Object>(1));
        contextBody.put("authnAttemptId", getDataFromContext(fromPost,"authnAttemptId"));
        contextBody.put("messageId", UUID.randomUUID().toString());
        contextBody.put("inResponseTo", getDataFromContext(fromPost,"messageId"));
        return contextBody;
    }

    private String getDataFromContext(JSONObject data, String key) {

        JSONObject theContext = data.getJSONObject("context");
        String returnValue = theContext.getString(key);
        return returnValue;
    }



    private JSONObject doPost(HttpPost post) throws Exception{
        JSONObject retVal = null;
        JSONObject obj = new JSONObject();
        JSONObject item = new JSONObject();
        JSONArray array = new JSONArray();

        CloseableHttpClient httpClient = null;

        try {
            item.put("Content-Type","application/json");
            //post.setHeader("client-key", config.clientKey()); Example from email
            item.put("code", parameters.get(OIDC_CODE).get(0));
            item.put("grant_type", "authorization_code");
            item.put("redirect_uri", config.RedirectUri());
            item.put("client_secret", config.ClientSecret());
            item.put("client_id", config.TenantName());
            array.put(item)


            if (!config.verifySSL()) {
// Create a trust manager that does not validate certificate chains
                httpClient = HttpClients.custom().setSSLHostnameVerifier(NoopHostnameVerifier.INSTANCE).build();
            } else {
                httpClient = HttpClientBuilder.create().build();
            }

            HttpResponse response = httpClient.execute(post);

            HttpEntity entity = response.getEntity();
            String content = EntityUtils.toString(entity);

            retVal = new JSONObject(content);


        } catch (Exception e) {
            throw new Exception(e.fillInStackTrace());

        } finally {
            if (httpClient != null) {
                try {
                    httpClient.close();
                } catch (Exception e) {
                    logger.error(loggerPrefix + "Error occurred trying to close the httpClient. Not fatal.");
                }
            }
        }

        return retVal;
    }


    private ArrayList<String> getChoices(JSONObject fromPost){
        ArrayList<String> retVal = new ArrayList<String>();
        System.out.println("Here is the returning String: " + fromPost.toString());

        JSONObject theContext = fromPost.getJSONObject("context");
        String inResponseTo = theContext.getString("messageId");
        System.out.println("inresponseTo: " + inResponseTo);
        String authNAttemptID = theContext.getString("authnAttemptId");
        System.out.println("authNAttemptID: " + authNAttemptID);

        JSONArray theChallenges = fromPost.getJSONObject("challengeMethods").getJSONArray("challenges");

        System.out.println("here are the challenges: " + theChallenges.length());

        for (int i = 0; i< theChallenges.length(); i++) {

            JSONObject thisJO = theChallenges.getJSONObject(i).getJSONArray("requiredMethods").getJSONObject(0);
            JSONArray methAttr = thisJO.getJSONArray("versions").getJSONObject(0).getJSONArray("methodAttributes");

            if (methAttr!=null && methAttr.length()>0 && methAttr.getJSONObject(0).getString("name").equalsIgnoreCase("METHOD_NOT_APPLICABLE")) {
//do nothing
            }
            else {
                retVal.add(thisJO.getString("displayName"));
            }

        }
        return retVal;
    }




    /**
     * Defines the possible outcomes from this node.
     */
    public static class SecurIDOutcomeProvider implements org.forgerock.openam.auth.node.api.OutcomeProvider {
        @Override
        public List<Outcome> getOutcomes(PreferredLocales locales, JsonValue nodeAttributes) {
            ResourceBundle bundle = locales.getBundleInPreferredLocale(BUNDLE,
                    SecurIDOutcomeProvider.class.getClassLoader());
            return ImmutableList.of(
                    new Outcome(SUCCESS, bundle.getString("SuccessOutcome")),
                    new Outcome(FAILURE, bundle.getString("FailureOutcome")),
                    new Outcome(CHALLENGE, bundle.getString("ChallengeOutcome")),
                    new Outcome(NOTENROLLED, bundle.getString("NotEnrolledOutcome")),
                    new Outcome(NOTSUPPORTED, bundle.getString("NotSupportedOutcome")),
                    new Outcome(CANCEL, bundle.getString("CancelOutcome")),
                    new Outcome(ERROR, bundle.getString("ErrorOutcome"))
            );
        }
    }


}