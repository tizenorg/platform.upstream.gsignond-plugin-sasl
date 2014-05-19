/* vi: set et sw=4 ts=4 cino=t0,(0: */
/* -*- Mode: C; indent-tabs-mode: nil; c-basic-offset: 4 -*- */
/*
 * This file is part of gsignond
 *
 * Copyright (C) 2012 Intel Corporation.
 *
 * Contact: Alexander Kanavin <alex.kanavin@gmail.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA
 */

/**
 * SECTION:gsignond-sasl-plugin
 * @short_description: SASL authentication plugin for gSSO single sign-on service
 * @see_also: #GSignondPlugin
 *
 * The SASL plugin provides a client-side implementation of several commonly
 * used SASL authentication mechanisms: ANONYMOUS, PLAIN, DIGEST-MD5, CRAM-MD5
 * and SCRAM-SHA-1. The plugin takes a mechanism name, and parameters specific
 * to that mechanism, and (depending on the mechanism) produces a final or an
 * intermidiate response string that the application transmits to the server. 
 * If the response string was intermidate, the server should return a challenge
 * string, which is supplied to the plugin, after which another final or 
 * intermediate response is produced. If a final response is returned then
 * no further challenges should arrive from the server, and authentication concludes.
 *
 * SASL framework is specified in <ulink url="http://tools.ietf.org/html/rfc4422">RFC 4422</ulink>.
 * 
 * Specific SASL mechanism specifications are: ANONYMOUS in <ulink url="http://tools.ietf.org/html/rfc4505">RFC 4505</ulink>,
 * PLAIN in <ulink url="http://tools.ietf.org/html/rfc4616">RFC 4616</ulink>,
 * CRAM-MD5 in <ulink url="http://tools.ietf.org/html/rfc2195">RFC 2195</ulink>,
 * DIGEST-MD5 in <ulink url="http://tools.ietf.org/html/rfc2831">RFC 2831</ulink>,
 * SCRAM-SHA-1 in <ulink url="http://tools.ietf.org/html/rfc5802">RFC 5802</ulink>.
 * 
 * The plugin implements the standard #GSignondPlugin interface, and after instantiating
 * a plugin object all interactions happen through that interface.
 * 
 * #GSignondPlugin:type property of the plugin object is set to "sasl".
 * 
 * #GSignondPlugin:mechanisms property of the plugin object is a list containing
 * the mechanisms above.
 * 
 * <refsect1><title>Authorization sequence</title></refsect1>
 * 
 * The authorization sequence begins with issuing gsignond_plugin_request_initial().
 * The @mechanism parameter should be set to one of the mechanisms listed above, and
 * the content of @session_data parameter depends on the mechanism and is described
 * in detail below. @identity_method_cache parameter is ignored.
 * 
 * The plugin responds to the request with one of the following signals:
 * - #GSignondPlugin::response-final This means the authorization sequence ended
 * successfully, and the final client response, encoded in base64, is delivered 
 * in @session_data parameter of the signal under "ResponseBase64" key. This 
 * signal concludes the sequence. The application then 
 * delivers the final response to the server, after which it's able to access
 * the services and resources on the server according to the specific protocol
 * it's implementing.
 * - #GSignondPlugin::response The plugin is requesting to send a response string
 * to the server. The string is also provided in @session_data parameter of the 
 * signal under "ResponseBase64" key, encoded in base64. The server is then 
 * supposed to return a challenge string which the application
 * delivers to the plugin with a gsignond_plugin_request() call via the 
 * @session_data parameter under "ChallengeBase64" 
 * key, encoded in base64. After that there may be another response-challenge 
 * cycle, or a final response via #GSignondPlugin::response-final signal.
 * - #GSignondPlugin::error An error has happened in the authorization sequence 
 * and it stops. See below for a description of possible errors.
 *
 * At any point the application can request to stop the authorization by calling
 * gsignond_plugin_cancel(). The plugin responds with an #GSignondPlugin::error signal
 * containing a %GSIGNOND_ERROR_SESSION_CANCELED error.
 * 
 * <refsect1><title>Code examples</title></refsect1>
 * 
 * <example>
 * <title>Using various SASL mechanisms</title>
 * <programlisting>
 * <xi:include href="../gsignond-sasl-example.listing" parse="text" xmlns:xi="http://www.w3.org/2001/XInclude"/>
 * </programlisting>
 * </example>
 * 
 * <refsect1><title>Errors issued via #GSignondPlugin::error signal</title></refsect1>
 * At any point in the authorization process the plugin may issue this signal
 * with an @error parameter that is a #GError. The @error has <literal>domain</literal> field set to
 * %GSIGNOND_ERROR. <literal>code</literal> field can be one of 
 * %GSIGNOND_ERROR_NOT_AUTHORIZED (which means an error in the
 * data provided for authorization), %GSIGNOND_ERROR_OPERATION_NOT_SUPPORTED 
 * (which means there was an error during sasl library initialization), or 
 * %GSIGNOND_ERROR_WRONG_STATE (which means an incorrect plugin API call was used).
 * <literal>message</literal> field tells additional details about the exact cause of the
 * error, and it's intended to help programming and debugging, but not meant
 * to be understood by end users directly (although it can be shown to them). 
 *
 * <refsect1><title>@session_data parameter in gsignond_plugin_request_initial()</title></refsect1>
 * The @session_data parameter contains different mechanism-specific parameters
 * as keys and string values. Here's a list of all possible parameters with 
 * explanations for each. See below for what each mechanism needs.
 *
 * - "ChallengeBase64" Initial server challenge, encoded in base64.
 * - gsignond_session_data_set_username() Authentication identity.
 * - gsignond_session_data_set_secret() The password of the authentication identity.
 * - gsignond_session_data_set_allowed_realms() List of allowed realms/domains, must exist when either "Hostname" or "Realm" is also supplied.
 * - "Authzid" The authorization identity. 
 * - "AnonymousToken" An anonymous token (for example an email address).
 * - "Service" The registered service name of the application service, e.g. “imap”. 
 * - "Hostname" Should be the local host name of the machine. 
 * - "Realm" The name of the authentication domain.
 * - "Qop" Quality of protection (QOP). Valid values are qop-auth, qop-int, and qop-conf. 
 * - "ScramSaltedPassword" 40 character long hex-encoded string with the user's hashed password.
 * - "CbTlsUnique" This property holds base64 encoded tls-unique channel binding 
 * data. As a hint, if you use GnuTLS, the API gnutls_session_channel_binding() 
 * can be used to extract channel bindings for a session. 
 *
 * <refsect1><title>How to use ANONYMOUS mechanism</title></refsect1>
 * Issue gsignond_plugin_request_initial() with @mechanism set to "ANONYMOUS"
 * and @session_data containing an anonymous token. 
 * The plugin will return the final response string immediately via
 * #GSignondPlugin::response-final signal.
 * 
 * <refsect1><title>How to use PLAIN mechanism</title></refsect1>
 * Issue gsignond_plugin_request_initial() with @mechanism set to "PLAIN"
 * and @session_data containing authentication identity, password, and (optionally)
 * authorization identity. 
 * The plugin will return the final response string immediately via
 * #GSignondPlugin::response-final signal.
 * 
 * <refsect1><title>How to use CRAM-MD5 mechanism</title></refsect1>
 * Issue gsignond_plugin_request_initial() with @mechanism set to "CRAM-MD5"
 * and @session_data containing authentication identity, password, and initial 
 * server challenge.
 * The plugin will return the final response string immediately via
 * #GSignondPlugin::response-final signal.
 *
 * <refsect1><title>How to use DIGEST-MD5 mechanism</title></refsect1>
 * Issue gsignond_plugin_request_initial() with @mechanism set to "DIGEST-MD5"
 * and @session_data containing authentication identity, password, service,
 * hostname, allowed realms list and initial server challenge.
 * Optionally, it can also include realm, QOP and authorization identity.
 *
 * The plugin will return a response for the server immediately via 
 * #GSignondPlugin::response signal. After receiving another challenge from 
 * the server (with gsignond_plugin_request()) the plugin will return a final response via 
 * #GSignondPlugin::response-final signal.
 *
 * <refsect1><title>How to use SCRAM-SHA-1 mechanism</title></refsect1>
 * Issue gsignond_plugin_request_initial() with @mechanism set to "SCRAM-SHA-1"
 * and @session_data containing authentication identity, initial
 * server challenge and password. The password can be provided via "ScramSaltedPassword" property
 * or if this property is absent, the normal password property is used. Optionally, also
 * authorization identity and channel binding data can be provided.
 *
 * This mechanism contains two rounds of response-challenge exchanges (as described
 * above) - gsignond_plugin_request_initial() should be followed by 
 * #GSignondPlugin::response, gsignond_plugin_request(), #GSignondPlugin::response,
 * gsignond_plugin_request(), and #GSignondPlugin::response-final. 
 *
 */

#include <stdlib.h>

#include <gsignond/gsignond-plugin-interface.h>
#include <gsignond/gsignond-error.h>
#include <gsignond/gsignond-log.h>
#include <gsignond/gsignond-utils.h>

#include "gsignond-sasl-plugin.h"

static void gsignond_plugin_interface_init (GSignondPluginInterface *iface);

G_DEFINE_TYPE_WITH_CODE (GSignondSaslPlugin, gsignond_sasl_plugin, 
                         G_TYPE_OBJECT,
                         G_IMPLEMENT_INTERFACE (GSIGNOND_TYPE_PLUGIN,
                                                gsignond_plugin_interface_init));

static void gsignond_sasl_plugin_cancel (GSignondPlugin *self)
{
    GError* error = g_error_new(GSIGNOND_ERROR, 
                                GSIGNOND_ERROR_SESSION_CANCELED,
                                "Session canceled");
    gsignond_plugin_error (self, error); 
    g_error_free(error);
}

static void _reset_session(GSignondSaslPlugin *self)
{
    if (self->session_data) {
        gsignond_dictionary_unref(self->session_data);
        self->session_data = NULL;
    }
    if (self->gsasl_session) {
        gsasl_finish(self->gsasl_session);
        self->gsasl_session = NULL;
    }
    
}

static void 
_do_gsasl_iteration(GSignondPlugin *plugin, const gchar* challenge)
{
    GSignondSaslPlugin *self = GSIGNOND_SASL_PLUGIN (plugin);
    
    char* output;
    int step_res = gsasl_step64(self->gsasl_session, challenge, &output);
    if (step_res != GSASL_OK && step_res != GSASL_NEEDS_MORE) {
        GError* error = g_error_new(GSIGNOND_ERROR, 
                                GSIGNOND_ERROR_NOT_AUTHORIZED,
                                "Authorization error %d",
                                step_res);
        gsignond_plugin_error (plugin, error); 
        g_error_free(error);
        return;
    }

    GSignondSessionData *response = gsignond_dictionary_new();
    gsignond_dictionary_set_string(response, "ResponseBase64", output);
    
    if (step_res == GSASL_OK) {
        _reset_session(self);
        gsignond_plugin_response_final(plugin, response);
    } else {
        gsignond_plugin_response(plugin, response);
    }
    
    free(output);
    gsignond_dictionary_unref(response);
    
}

static int
_set_gsasl_property(Gsasl_session * gsasl_session, 
                    Gsasl_property gsasl_property,
                    const gchar* value)
{
    if (value == NULL)
        return GSASL_NO_CALLBACK;
    gsasl_property_set(gsasl_session, gsasl_property, value);
    return GSASL_OK;
}

static int
_gsasl_callback (Gsasl * gsasl_context, 
                 Gsasl_session * gsasl_session, 
                 Gsasl_property gsasl_property)
{
    GSignondSaslPlugin *self = gsasl_callback_hook_get(gsasl_context);
    
    INFO ("Gsasl callback invoked, for property %d", gsasl_property);

    GSignondSessionData *session_data = self->session_data;
    if (session_data == NULL)
        return GSASL_NO_CALLBACK;
    
    switch (gsasl_property)
    {
        case GSASL_AUTHID:
            return _set_gsasl_property(gsasl_session, gsasl_property, 
                                       gsignond_session_data_get_username(
                                           session_data));
            break;
        case GSASL_AUTHZID:
            return _set_gsasl_property(gsasl_session, gsasl_property, 
                                       gsignond_dictionary_get_string(
                                           session_data, "Authzid"));
            break;
        case GSASL_PASSWORD:
            return _set_gsasl_property(gsasl_session, gsasl_property, 
                                       gsignond_session_data_get_secret(
                                           session_data));
            break;
        case GSASL_ANONYMOUS_TOKEN:
            return _set_gsasl_property(gsasl_session, gsasl_property, 
                                       gsignond_dictionary_get_string(
                                           session_data, "AnonymousToken"));
            break;
        case GSASL_SERVICE:
            return _set_gsasl_property(gsasl_session, gsasl_property, 
                                       gsignond_dictionary_get_string(
                                           session_data, "Service"));
            break;
        case GSASL_HOSTNAME:
            return _set_gsasl_property(gsasl_session, gsasl_property, 
                                       gsignond_dictionary_get_string(
                                           session_data, "Hostname"));
            break;
        case GSASL_GSSAPI_DISPLAY_NAME:
            return _set_gsasl_property(gsasl_session, gsasl_property, 
                                       gsignond_dictionary_get_string(
                                           session_data, "GssapiDisplayName"));
            break;
        case GSASL_PASSCODE:
            return _set_gsasl_property(gsasl_session, gsasl_property, 
                                       gsignond_dictionary_get_string(
                                           session_data, "Passcode"));
            break;
        case GSASL_SUGGESTED_PIN:
            return _set_gsasl_property(gsasl_session, gsasl_property, 
                                       gsignond_dictionary_get_string(
                                           session_data, "SuggestedPin"));
            break;
        case GSASL_PIN:
            return _set_gsasl_property(gsasl_session, gsasl_property, 
                                       gsignond_dictionary_get_string(
                                           session_data, "Pin"));
            break;
        case GSASL_REALM:
            return _set_gsasl_property(gsasl_session, gsasl_property, 
                                       gsignond_dictionary_get_string(
                                           session_data, "Realm"));
            break;
        case GSASL_DIGEST_MD5_HASHED_PASSWORD:
            return _set_gsasl_property(gsasl_session, gsasl_property, 
                                       gsignond_dictionary_get_string(
                                           session_data, "DigestMd5HashedPassword"));
            break;
        case GSASL_QOPS:
            return _set_gsasl_property(gsasl_session, gsasl_property, 
                                       gsignond_dictionary_get_string(
                                           session_data, "Qops"));
            break;
        case GSASL_QOP:
            return _set_gsasl_property(gsasl_session, gsasl_property, 
                                       gsignond_dictionary_get_string(
                                           session_data, "Qop"));
            break;
        case GSASL_SCRAM_ITER:
            return _set_gsasl_property(gsasl_session, gsasl_property, 
                                       gsignond_dictionary_get_string(
                                           session_data, "ScramIter"));
            break;
        case GSASL_SCRAM_SALT:
            return _set_gsasl_property(gsasl_session, gsasl_property, 
                                       gsignond_dictionary_get_string(
                                           session_data, "ScramSalt"));
            break;
        case GSASL_SCRAM_SALTED_PASSWORD:
            return _set_gsasl_property(gsasl_session, gsasl_property, 
                                       gsignond_dictionary_get_string(
                                           session_data, "ScramSaltedPassword"));
            break;
        case GSASL_CB_TLS_UNIQUE:
            return _set_gsasl_property(gsasl_session, gsasl_property, 
                                       gsignond_dictionary_get_string(
                                           session_data, "CbTlsUnique"));
            break;
        default:
            break;
    }
     
    return GSASL_NO_CALLBACK;
}

static void gsignond_sasl_plugin_request (
    GSignondPlugin *plugin, GSignondSessionData *session_data)
{
    GSignondSaslPlugin *self = GSIGNOND_SASL_PLUGIN (plugin);

    if (!self->gsasl_session) {
        GError* error = g_error_new(GSIGNOND_ERROR, 
                                GSIGNOND_ERROR_WRONG_STATE,
                                "request_initial needs to be issued first");
        gsignond_plugin_error (plugin, error); 
        g_error_free(error);
        return;
    }
    _do_gsasl_iteration(plugin, gsignond_dictionary_get_string(session_data, "ChallengeBase64"));
}

static void gsignond_sasl_plugin_request_initial (
    GSignondPlugin *plugin, GSignondSessionData *session_data, 
    GSignondDictionary *identity_method_cache,
    const gchar *mechanism)
{
    GSignondSaslPlugin *self = GSIGNOND_SASL_PLUGIN (plugin);
    gboolean realm_ok = FALSE;
    gboolean host_ok = FALSE;
    const gchar *realm;
    const gchar *host;
    GSequence *allowed_realms;
    GSequenceIter *realm_iter;

    if (!self->gsasl_context) {
        GError *error = g_error_new (GSIGNOND_ERROR, 
                                     GSIGNOND_ERROR_OPERATION_NOT_SUPPORTED,
                                     "Couldn't initialize gsasl library");
        gsignond_plugin_error (plugin, error); 
        g_error_free (error);
        return;
    }
    realm = gsignond_session_data_get_realm (session_data);
    host = gsignond_dictionary_get_string(session_data, "Hostname");
    allowed_realms = gsignond_session_data_get_allowed_realms (session_data);
    if (allowed_realms) {
        for (realm_iter = g_sequence_get_begin_iter (allowed_realms);
             !g_sequence_iter_is_end (realm_iter);
             realm_iter = g_sequence_iter_next (realm_iter)) {
            const gchar *item = (const gchar *) g_sequence_get (realm_iter);
            if (realm) {
                if (g_strcmp0 (realm, item) == 0)
                    realm_ok = TRUE;
            }
            if (host) {
                if (gsignond_is_host_in_domain (host, item))
                    host_ok = TRUE;
            }
        }
        g_sequence_free (allowed_realms);
    }
    if (realm && !realm_ok) {
        GError *error = g_error_new (GSIGNOND_ERROR,
                                     GSIGNOND_ERROR_NOT_AUTHORIZED,
                                     "Unauthorized realm");
        gsignond_plugin_error (plugin, error);
        g_error_free (error);
        return;
    }
    if (host && !host_ok) {
        GError *error = g_error_new (GSIGNOND_ERROR,
                                     GSIGNOND_ERROR_NOT_AUTHORIZED,
                                     "Unauthorized hostname");
        gsignond_plugin_error (plugin, error);
        g_error_free (error);
        return;
    }
    
    _reset_session(self);

    int res = gsasl_client_start (self->gsasl_context, 
                                  mechanism, &self->gsasl_session);
    
    if (res != GSASL_OK) {
        GError *error = g_error_new (GSIGNOND_ERROR, 
                                     GSIGNOND_ERROR_OPERATION_NOT_SUPPORTED,
                                     "Couldn't initialize gsasl session, error %d",
                                     res);
        gsignond_plugin_error (plugin, error); 
        g_error_free (error);
        return;
    }
    gsignond_dictionary_ref(session_data);
    self->session_data = session_data;
    _do_gsasl_iteration(plugin, gsignond_dictionary_get_string(session_data, "ChallengeBase64"));
}

static void gsignond_sasl_plugin_user_action_finished (
    GSignondPlugin *plugin, 
    GSignondSessionData *session_data)
{
    GError* error = g_error_new(GSIGNOND_ERROR, 
                            GSIGNOND_ERROR_WRONG_STATE,
                            "SASL plugin doesn't support user actions");
    gsignond_plugin_error (plugin, error); 
    g_error_free(error);
    return;
}

static void gsignond_sasl_plugin_refresh (
    GSignondPlugin *plugin, 
    GSignondSessionData *session_data)
{
    GError* error = g_error_new(GSIGNOND_ERROR, 
                            GSIGNOND_ERROR_WRONG_STATE,
                            "SASL plugin doesn't support refresh");
    gsignond_plugin_error (plugin, error); 
    g_error_free(error);
    return;
}

static void
gsignond_plugin_interface_init (GSignondPluginInterface *iface)
{
    iface->cancel = gsignond_sasl_plugin_cancel;
    iface->request_initial = gsignond_sasl_plugin_request_initial;
    iface->request = gsignond_sasl_plugin_request;
    iface->user_action_finished = gsignond_sasl_plugin_user_action_finished;
    iface->refresh = gsignond_sasl_plugin_refresh;
}

static void
gsignond_sasl_plugin_init (GSignondSaslPlugin *self)
{
    self->gsasl_context = NULL;
    self->gsasl_session = NULL;
    int rc;
     
    if ((rc = gsasl_init (&self->gsasl_context)) != GSASL_OK) {
        ERR ("Cannot initialize libgsasl (%d): %s",rc, gsasl_strerror (rc));
    } else {
        gsasl_callback_hook_set(self->gsasl_context, self);
        gsasl_callback_set (self->gsasl_context, _gsasl_callback);
    }
}

static void
gsignond_sasl_plugin_finalize (GObject *gobject)
{
    GSignondSaslPlugin *self = GSIGNOND_SASL_PLUGIN (gobject);

    _reset_session(self);
    if (self->gsasl_context)
        gsasl_done(self->gsasl_context);
        
    /* Chain up to the parent class */
    G_OBJECT_CLASS (gsignond_sasl_plugin_parent_class)->finalize (gobject);
}

enum
{
    PROP_0,
    
    PROP_TYPE,
    PROP_MECHANISMS
};

static void
gsignond_sasl_plugin_set_property (GObject      *object,
                                       guint         property_id,
                                       const GValue *value,
                                       GParamSpec   *pspec)
{
    switch (property_id)
    {
        default:
            G_OBJECT_WARN_INVALID_PROPERTY_ID (object, property_id, pspec);
            break;
    }
}

static void
gsignond_sasl_plugin_get_property (GObject    *object,
                                       guint       prop_id,
                                       GValue     *value,
                                       GParamSpec *pspec)
{
    GSignondSaslPlugin *sasl_plugin = GSIGNOND_SASL_PLUGIN (object);

    gchar *empty_mechanisms[] = { NULL };
    char *mechanisms;
    
    switch (prop_id)
    {
        case PROP_TYPE:
            if (sasl_plugin->gsasl_context)
                g_value_set_string (value, "sasl");
            else
                g_value_set_string (value, "");
            break;
        case PROP_MECHANISMS:
            if (sasl_plugin->gsasl_context &&
                gsasl_client_mechlist (sasl_plugin->gsasl_context, 
                                       &mechanisms) == GSASL_OK) {
                gchar ** mechanism_list = g_strsplit(mechanisms, " ", 0);
                g_value_set_boxed(value, mechanism_list);
                g_strfreev(mechanism_list);
                free(mechanisms);
            } else
                g_value_set_boxed (value, empty_mechanisms);
            break;
            
        default:
            G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
            break;
    }
}

static void
gsignond_sasl_plugin_class_init (GSignondSaslPluginClass *klass)
{
    GObjectClass *gobject_class = G_OBJECT_CLASS (klass);
    
    gobject_class->set_property = gsignond_sasl_plugin_set_property;
    gobject_class->get_property = gsignond_sasl_plugin_get_property;
    gobject_class->finalize = gsignond_sasl_plugin_finalize;
    
    g_object_class_override_property (gobject_class, PROP_TYPE, "type");
    g_object_class_override_property (gobject_class, PROP_MECHANISMS, 
                                      "mechanisms");
}
