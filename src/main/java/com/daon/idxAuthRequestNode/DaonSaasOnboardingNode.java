/*
 * The contents of this file are subject to the terms of the Common Development and
 * Distribution License (the License). You may not use this file except in compliance with the
 * License.
 *
 * You can obtain a copy of the License at legal/CDDLv1.0.txt. See the License for the
 * specific language governing permission and limitations under the License.
 *
 * When distributing Covered Software, include this CDDL Header Notice in each file and include
 * the License file at legal/CDDLv1.0.txt. If applicable, add the following below the CDDL
 * Header, with the fields enclosed by brackets [] replaced by your own identifying
 * information: "Portions copyright [year] [name of copyright owner]".
 *
 * Copyright 2017-2018 ForgeRock AS.
 */


package com.daon.idxAuthRequestNode;

import static com.daon.idxAuthRequestNode.DaonSaasOnboardingConstants.ERROR;
import static com.daon.idxAuthRequestNode.DaonSaasOnboardingConstants.OIDC_CODE;
import static com.daon.idxAuthRequestNode.DaonSaasOnboardingConstants.SESSION_STATE;
import static com.daon.idxAuthRequestNode.DaonSaasOnboardingConstants.STATE;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.math.BigInteger;
import java.net.URLEncoder;
import java.nio.Buffer;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.spec.RSAPublicKeySpec;
import java.util.*;

import javax.inject.Inject;

import io.grpc.xds.shaded.io.envoyproxy.envoy.api.v2.core.HttpUri;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.lang3.exception.ExceptionUtils;
import org.apache.hc.client5.http.impl.classic.BasicHttpClientResponseHandler;
import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.methods.HttpUriRequest;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.protocol.HttpContext;
import org.apache.http.util.EntityUtils;
import org.forgerock.http.protocol.Request;
import org.forgerock.http.protocol.Response;
import org.forgerock.json.JsonValue;
import org.forgerock.openam.annotations.sm.Attribute;
import org.forgerock.openam.auth.node.api.AbstractDecisionNode;
import org.forgerock.openam.auth.node.api.Action;
import org.forgerock.openam.auth.node.api.Node;
import org.forgerock.openam.auth.node.api.NodeProcessException;
import org.forgerock.openam.auth.node.api.TreeContext;
import org.forgerock.util.i18n.PreferredLocales;
import org.json.JSONArray;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.inject.assistedinject.Assisted;
import com.sun.identity.authentication.spi.RedirectCallback;
import com.sun.identity.sm.RequiredValueValidator;


/**x
 * A node that performs SaaS Onboarding
 */
@Node.Metadata(outcomeProvider  = DaonSaasOnboardingNode.OutcomeProvider.class,
               configClass      = DaonSaasOnboardingNode.Config.class,
               tags 			= {"marketplace", "trustnetwork"})
public class DaonSaasOnboardingNode extends AbstractDecisionNode 
{
    private final Logger logger = LoggerFactory.getLogger(DaonSaasOnboardingNode.class);
    private final String loggerPrefix = "[Daon SaaS Onboarding Node][Marketplace] ";
    private final Config config;
    private JSONArray signingKeys;

    /**
     * Configuration for the node.
     */
    public interface Config 
    {
    	/**
         * HostName for the SaaS Onboarding endpoint
         *
         * @return the HostName
         */
    	@Attribute(order = 100, validators = {RequiredValueValidator.class})
        String HostName();
    	
    	/**
         * Tenant for the SaaS Onboarding endpoint
         *
         * @return the Tenant
         */
    	@Attribute(order = 200, validators = {RequiredValueValidator.class})
        String TenantName();
    	
    	/**
         * Redirect URI for the SaaS Onboarding endpoint
         *
         * @return the Redirect URI
         */
    	@Attribute(order = 300, validators = {RequiredValueValidator.class})
        String RedirectUri();
    	
    	/**
         * Client secret for use in retrieving the ID Token
         *
         * @return the Client Secret
         */
    	@Attribute(order = 400, validators = {RequiredValueValidator.class})
        String ClientSecret();
    	
    	/**
         * Name of the field in shared state that contains the Login hint (user name or ID) for the SaaS Onboarding endpoint
         *
         * @return the Login hint
         */
    	@Attribute(order = 500)
        String LoginHintField();
    }


    /**
     * Create the node using Guice injection. Just-in-time bindings can be used to obtain instances of other classes
     * from the plugin.
     *
     * @param config The service config.
     * @throws NodeProcessException If the configuration was not valid.
     */
    @Inject
    public DaonSaasOnboardingNode(@Assisted Config config) throws NodeProcessException 
    {
        this.config = config;
        if (StringUtils.isEmpty(config.HostName()) || StringUtils.isEmpty(config.TenantName())
				|| StringUtils.isEmpty(config.RedirectUri()) || StringUtils.isEmpty(config.ClientSecret())) 
        {
			throw new NodeProcessException("One or more config values required for Onboarding are empty.");
        }
        
        this.signingKeys = getSigningKeys();
        if (this.signingKeys.isEmpty())
	    {
	    	throw new NodeProcessException("The JWKS endpoint did not contain any signature verification keys.");
	    }
    }

    @Override
    public Action process(TreeContext context) throws NodeProcessException 
    {
    	try
        {
        	logger.debug(loggerPrefix + "Started");
        	Map<String, List<String>> parameters = context.request.parameters;

			System.out.println("parameters: "+ parameters);
        	JsonValue sharedState = context.sharedState;

        	if (parameters.containsKey(ERROR))
        	{
				System.out.println("Key contains error");
        		throw new NodeProcessException("Onboarding failed:  " + parameters.get(ERROR).get(0));
        	}

        	if (parameters.containsKey(OIDC_CODE))
        	{
				System.out.println("Value for parameters.containsKey()");
				if (sharedState.isDefined(OIDC_CODE))
				{
					// We have looped back from an unsuccessful attempt, remove sharedState and continue
					System.out.println("Inside sharedState.isDefined(OIDC_CODE)");
					sharedState.remove(OIDC_CODE);
				} 
				else 
				{
					// We have returned from redirect
					System.out.println("In else statement now on line 181");
					sharedState.put(OIDC_CODE, parameters.get(OIDC_CODE).get(0));


					//Builds body of request
//					OkHttpClient client = new OkHttpClient().newBuilder().build();
//					RequestBody body = new FormBody.Builder()
//							.add("code", parameters.get(OIDC_CODE).get(0))
//							.add("grant_type", "authorization_code")
//							.add("redirect_uri", config.RedirectUri())
//							.add("client_secret", config.ClientSecret())
//							.add("client_id", config.TenantName())
//							.build();

					JSONObject obj = new JSONObject();
					JSONObject item = new JSONObject();
					JSONArray json = new JSONArray();

					CloseableHttpClient httpClient = null;
					String url = "https://" + config.HostName() + "/auth/realms/" + config.TenantName() + "/protocol/openid-connect/token";

					//final HttpPost httpPost = new HttpPost(url);
					HttpPost post = new HttpPost(url);
					System.out.println("Line 201 outside try statement");
					try {
						System.out.println("Line 202 try statement");
						post.setHeader("Content-Type","application/json");
						//post.setHeader("client-key", config.clientKey()); Example from email
						item.put("code", parameters.get(OIDC_CODE).get(0));
						post.setHeader("grant_type", "authorization_code");
						item.put("redirect_uri", config.RedirectUri());
						item.put("client_secret", config.ClientSecret());
						item.put("client_id", config.TenantName());
						json.put(item);

						String string_json = json.toString();
						System.out.println("string_json: " + string_json);
						final StringEntity entity = new StringEntity(string_json);
						System.out.println("Entity: " + entity);
						post.setEntity(entity);

						httpClient = HttpClientBuilder.create().build();


//						HttpResponse response = httpClient.execute(post);
//
//						HttpEntity responseEntity = response.getEntity();
//						String content = EntityUtils.toString(responseEntity);
//
//						JSONObject retVal = new JSONObject(content);



//					//Creates request to the url with that body in it
//					Buffer buffer = new Buffer();
//					body.writeTo(buffer);
//					Request request = new Request.Builder()
//							.url("https://" + config.HostName() + "/auth/realms/" + config.TenantName() + "/protocol/openid-connect/token")
//							.addHeader("Content-Type", "application/x-www-form-urlencoded")
//							.post(body)
//							.build();
					//Response response = client.newCall(request).execute()
					try (CloseableHttpResponse response = httpClient.execute(post))
					{
						System.out.println("Inside of closeable http request try statement in main process...");
//						 if (!response.isSuccessful())
//						 {
//							 if (response.code() == 400)
//							 {
//								 throw new NodeProcessException("400: Bad Request. "+ response.body().string());
//							 }
//							 else
//							 {
//								 throw new NodeProcessException("Unexpected code: " + response.code() + ". " + response.body().string());
//							 }
//						 }

				         // Get response body


						HttpEntity responseEntity = response.getEntity();
						String content = EntityUtils.toString(responseEntity);

						JSONObject retVal = new JSONObject(content);
						System.out.println("retVal: " + retVal);
						//String responseBody = response.body().string();

				         Base64.Decoder decoder = Base64.getUrlDecoder();
				         JSONObject jsonResponse = new JSONObject(responseEntity);
				         String token = jsonResponse.getString("id_token");
				         String[] parts = token.split("\\.");
				         if (!verifyToken(parts))
				         {
				        	 throw new NodeProcessException("Token could not be verified");
				         }
				         JSONObject payload = new JSONObject(new String(decoder.decode(parts[1])));
				         sharedState.put("payload", payload);
				         logger.debug(loggerPrefix + "Exiting with True Outcome");
				         return Action.goTo(DaonSaasOnboardingNode.TRUE_OUTCOME_ID).replaceSharedState(sharedState).build();
					}
				} catch (Exception e) {
					throw new Exception(e.fillInStackTrace());
				}
				} //else
			}
        	System.out.println("Did not get into OIDC if statement...");
        	// Redirecting to SaaS Onboarding site
			String encodedUri = URLEncoder.encode(config.RedirectUri(), "UTF-8");
        	String baseUrl = "https://" + config.HostName() + 
        			"/auth/realms/" + config.TenantName() + 
        			"/protocol/openid-connect/auth?response_type=code&client_id=" + config.TenantName() +
        			"&scope=openid%20document%20phone&redirect_uri=" + encodedUri;
        	
        	String loginHint = null;
        	if (config.LoginHintField() != null)
        	{
        		logger.debug(loggerPrefix + "Login hint field = " + config.LoginHintField());
        		if (sharedState.isDefined(config.LoginHintField()))
        		{
        			loginHint = sharedState.get(config.LoginHintField()).asString();
        			logger.debug(loggerPrefix + "Login Hint = " + loginHint);
        			baseUrl = baseUrl + "&" + loginHint;
        		}
        		else
        		{
        			logger.warn(loggerPrefix + config.LoginHintField() + " is not in shared state!");
        		}
        	}
        	
        	byte[] randomBytes = new byte[32];
        	SecureRandom random = SecureRandom.getInstance("DRBG");
        	random.nextBytes(randomBytes);
        	String state = convertBytesToHex(randomBytes);
        	String serverUrl = baseUrl + "&state=" + state;
        	
			RedirectCallback redirectCallback = new RedirectCallback(serverUrl, null, "GET");
			redirectCallback.setTrackingCookie(true);
			logger.debug(loggerPrefix + "Redirecting to " + serverUrl);
			return Action.send(redirectCallback).build();
            
        }
        catch (Exception e) 
        {
            logger.error(loggerPrefix + "Exception occurred: " + e.getStackTrace());
            logger.error(loggerPrefix + "Error = " + e.getMessage());
            logger.debug(ExceptionUtils.getStackTrace(e));
            context.getStateFor(this).putShared(loggerPrefix + "Exception", new Date() + ": " + e.getMessage());
            StringWriter sw = new StringWriter();
            PrintWriter pw = new PrintWriter(sw);
            e.printStackTrace(pw);
            context.getStateFor(this).putShared(loggerPrefix + "StackTrace", new Date() + ": " + sw.toString());
            logger.debug(loggerPrefix + "Exiting with Error Outcome");
            return Action.goTo("Error").build();
        }
    }

    private String convertBytesToHex(byte[] bytes)
    {

    	StringBuilder result = new StringBuilder();
    	for (byte temp : bytes)
    	{
    		result.append(String.format("%02x",  temp));
    	}
    	return result.toString();
    }
    
    
    private JSONArray getSigningKeys()
	{

		JSONArray signingKeys = new JSONArray();
		
		CloseableHttpClient httpClient = HttpClientBuilder.create().build();

		String url = "https://" + config.HostName() + "/auth/realms/" + config.TenantName() + "/protocol/openid-connect/certs";
		HttpGet get = new HttpGet(url);
		try (CloseableHttpResponse response = httpClient.execute(get))
		{
			String responseBody = EntityUtils.toString(response.getEntity(), StandardCharsets.UTF_8);


			JSONObject object = new JSONObject(responseBody);
			JSONArray array = object.getJSONArray("keys");
			JSONObject jsonObject = array.getJSONObject(0);

			Iterator<String> keys = jsonObject.keys();
			Boolean use_flag = false, kty_flag = false, n_e_flag = false;
			Integer num_keys = 0;
	        while(keys.hasNext())
	        {
	        	String key = keys.next();
				Object value = jsonObject.get(key);

				if(key != null) num_keys = num_keys + 1;

				switch(key){
					case "use":
						if(value.equals("sig")) use_flag = true;
					case "kty":
						if(value.equals("RSA")) {
							kty_flag = true;
						}
				}

				if(value.toString().contains("a") && value.toString().contains("e")) n_e_flag = true;

	        	if (use_flag && kty_flag && n_e_flag) signingKeys.put(key);

	        }
			logger.debug("number of keys" + num_keys);
		httpClient.close();
		}
		catch(Exception e)
		{
			logger.debug(loggerPrefix + "Error getting signing keys:  " + e.getMessage());
		}
	        
	    return signingKeys;
	}
    
    
    private boolean verifyToken(String[] parts)
    {
    	Base64.Decoder decoder = Base64.getUrlDecoder();
    	
    	try
    	{
    		JSONObject header  = new JSONObject(new String(decoder.decode(parts[0])));
    		String hdrKid = header.getString("kid");
    		JSONObject signingKey = getSigningKey(hdrKid);
    		BigInteger modulus = new BigInteger(1, decoder.decode(signingKey.getString("n")));
    		BigInteger exponent = new BigInteger(1, decoder.decode(signingKey.getString("e")));
    		byte[] signingInfo = String.join(".",parts[0],parts[1]).getBytes(StandardCharsets.UTF_8);
    		byte[] b64DecodedSig = decoder.decode(parts[2]);
    		PublicKey pub = KeyFactory.getInstance("RSA").generatePublic(new RSAPublicKeySpec(modulus, exponent));
    		Signature verifier = Signature.getInstance("SHA256withRSA");
    		verifier.initVerify(pub);
    		verifier.update(signingInfo);
    		return verifier.verify(b64DecodedSig);
    	}
    	catch(Exception e)
    	{
    		logger.warn(loggerPrefix + "Error verifying token:  " + e.getMessage());
    		return(false);
    	}
    }
    
    
    private JSONObject getSigningKey(String kid) throws NodeProcessException
    {
    	for (int i = 0; i < signingKeys.length(); i++)
		{
			JSONObject key = signingKeys.getJSONObject(i);
			if (key.get("kid").equals(kid))
			{
				return key;
			}
		}
    	throw new NodeProcessException("Unable to find a signing key that matches the kid: " + kid);
    }
	public static final class OutcomeProvider implements org.forgerock.openam.auth.node.api.OutcomeProvider {
		/**
		 * Outcomes Ids for this node.
		 */
		static final String SUCCESS_OUTCOME = "True";
		static final String ERROR_OUTCOME = "Error";

		private static final String BUNDLE = DaonSaasOnboardingNode.class.getName();

		@Override
		public List<Outcome> getOutcomes(PreferredLocales locales, JsonValue nodeAttributes) {

			ResourceBundle bundle = locales.getBundleInPreferredLocale(BUNDLE, OutcomeProvider.class.getClassLoader());

			List<Outcome> results = new ArrayList<>(
					Arrays.asList(
							new Outcome(SUCCESS_OUTCOME, SUCCESS_OUTCOME)
					)
			);

			results.add(new Outcome(ERROR_OUTCOME, ERROR_OUTCOME));

			return Collections.unmodifiableList(results);
		}



	}
}
