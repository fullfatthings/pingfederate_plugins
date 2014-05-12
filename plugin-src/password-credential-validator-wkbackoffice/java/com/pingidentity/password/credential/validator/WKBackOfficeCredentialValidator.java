/***************************************************************************
 * Copyright (C) 2012 Ping Identity Corporation
 * All rights reserved.
 *
 * The contents of this file are subject to the terms of the
 * Ping Identity Corporation SDK Developer Guide.
 *
 **************************************************************************/

package com.pingidentity.password.credential.validator;

import java.util.Collections;

// Imports for http integration.
import java.net.URLConnection;
import java.net.HttpURLConnection;
import java.net.URL;
import java.io.IOException;
import java.net.MalformedURLException;
import javax.xml.bind.DatatypeConverter;

import org.sourceid.saml20.adapter.attribute.AttributeValue;
import org.sourceid.saml20.adapter.conf.Configuration;
import org.sourceid.saml20.adapter.gui.TextFieldDescriptor;
import org.sourceid.saml20.adapter.gui.CheckBoxFieldDescriptor;
import org.sourceid.saml20.adapter.gui.validation.impl.RequiredFieldValidator;
import org.sourceid.util.log.AttributeMap;

import com.pingidentity.sdk.GuiConfigDescriptor;
import com.pingidentity.sdk.PluginDescriptor;
import com.pingidentity.sdk.password.PasswordCredentialValidator;
import com.pingidentity.sdk.password.PasswordValidationException;

/**
 * A password credential validator containing a single username and password pair.
 * <p>
 * Not for actual deployments but useful for POCs and as an SDK example.
 */
public class WKBackOfficeCredentialValidator implements PasswordCredentialValidator
{
    private static String URL = "URL";
    private static String TYPE = "WKBackOffice Credential Validator";
    private static String IGNORE_STRICT_SSL = "Ensure Valid SSL certificate?";

    String url = null;
    Boolean ignoreStrictSSL = false;

    /**
     * This method is called by the PingFederate server to push configuration values entered by the administrator via
     * the dynamically rendered GUI configuration screen in the PingFederate administration console. Your implementation
     * should use the {@link Configuration} parameter to configure its own internal state as needed. <br/>
     * <br/>
     * Each time the PingFederate server creates a new instance of your plugin implementation this method will be
     * invoked with the proper configuration. All concurrency issues are handled in the server so you don't need to
     * worry about them here. The server doesn't allow access to your plugin implementation instance until after
     * creation and configuration is completed.
     *
     * @param configuration
     *            the Configuration object constructed from the values entered by the user via the GUI.
     */
    @Override
    public void configure(Configuration configuration)
    {
        this.url = configuration.getFieldValue(URL);
        this.ignoreStrictSSL = configuration.getBooleanFieldValue(IGNORE_STRICT_SSL);
    }

    /**
     * Returns the {@link PluginDescriptor} that describes this plugin to the PingFederate server. This includes how
     * PingFederate will render the plugin in the administrative console, and metadata on how PingFederate will treat
     * this plugin at runtime.
     *
     * @return A {@link PluginDescriptor} that describes this plugin to the PingFederate server.
     */
    @Override
    public PluginDescriptor getPluginDescriptor()
    {
        RequiredFieldValidator requiredFieldValidator = new RequiredFieldValidator();

        GuiConfigDescriptor guiDescriptor = new GuiConfigDescriptor();
        guiDescriptor.setDescription(TYPE);

        TextFieldDescriptor urlFieldDescriptor = new TextFieldDescriptor(URL, URL);
        urlFieldDescriptor.addValidator(requiredFieldValidator);
        guiDescriptor.addField(urlFieldDescriptor);

        CheckBoxFieldDescriptor strictSSL = new CheckBoxFieldDescriptor(IGNORE_STRICT_SSL, "");
        guiDescriptor.addField(strictSSL);

        // TextFieldDescriptor usernameFieldDescriptor = new TextFieldDescriptor(USERNAME, USERNAME);
        // usernameFieldDescriptor.addValidator(requiredFieldValidator);
        // guiDescriptor.addField(usernameFieldDescriptor);

        // TextFieldDescriptor passwordFieldDescriptor = new TextFieldDescriptor(PASSWORD, PASSWORD, true);
        // passwordFieldDescriptor.addValidator(requiredFieldValidator);
        // guiDescriptor.addField(passwordFieldDescriptor);

        PluginDescriptor pluginDescriptor = new PluginDescriptor(TYPE, this, guiDescriptor);
        pluginDescriptor.setAttributeContractSet(Collections.singleton(URL));
        pluginDescriptor.setSupportsExtendedContract(false);
        return pluginDescriptor;
    }

    /**
     * Validates the given username and password in the manner appropriate to the plugin implementation.
     *
     * @param username
     *            the given username/id
     * @param password
     *            the given password
     * @return An AttributeMap with at least one entry representing the principal. The key of the entry does not matter,
     *         so long as the map is not empty. If the map is empty or null, the username and password combination is
     *         considered invalid.
     * @throws PasswordValidationException
     *             runtime exception when the validator cannot process the username and password combination due to
     *             system failure such as data source off line, host name unreachable, etc.
     */
    @Override
    public AttributeMap processPasswordCredential(String username, String password) throws PasswordValidationException
    {
        AttributeMap attributeMap = null;
        String url = this.url;
        String charset = "UTF-8";
        int status = 0;


        if (username == null && password == null)
        {
            throw new PasswordValidationException("Invalid username and/or password");
        }

        try {
            HttpURLConnection httpConnection = (HttpURLConnection) new URL(url).openConnection();
            String encodedAuth = DatatypeConverter.printBase64Binary((username + ":" + password).getBytes("UTF-8"));
            httpConnection.setRequestProperty("Authorization", "Basic " + encodedAuth);
            status = httpConnection.getResponseCode();
        }
        catch (MalformedURLException badURLerror) {
            throw new PasswordValidationException("URL is malformed: " + url);
        }
        catch (IOException connectionError) {
            throw new PasswordValidationException("Cannot connect to back office at " + url);
        }

        if (status == 200)
        {
            attributeMap = new AttributeMap();
            attributeMap.put("test key", new AttributeValue("test value"));
        }
        else
        {
            // authentication failed return null or an empty map
            return null;
        }

        return attributeMap;
    }
}
