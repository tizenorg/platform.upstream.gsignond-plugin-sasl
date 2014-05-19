/* PLEASE NOTE: this example is meant for SASL plugin developers. If you're
 * an application developer who wants to use this plugin, please refer to
 * libgsignon-glib documentation here:
 * http://gsignon-docs.accounts-sso.googlecode.com/git/libgsignon-glib/index.html
 */
/*
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

#include <gsignond/gsignond-session-data.h>
#include <gsignond/gsignond-plugin-interface.h>
#include <gsignond/gsignond-error.h>
#include <gsignond/gsignond-utils.h>
#include "gsignond-sasl-plugin.h"

static const gchar* allowed_realms[] = { "megahostname", NULL };

//this callback prints the received final response
//the final response should also be sent to the server
static void final_response_callback(GSignondPlugin* plugin, GSignondSessionData* result,
                     gpointer user_data)
{
    const gchar* response = gsignond_dictionary_get_string(result,
                                                           "ResponseBase64");
    g_print("Authenticated successfully, got final response:\n%s\n",
             response);
}

static void response_callback(GSignondPlugin* plugin, GSignondSessionData* result,
                     gpointer user_data)
{
    //print the received intermediate response
    const gchar* response = gsignond_dictionary_get_string(result,
                                                           "ResponseBase64");
    g_print("Authenticated successfully, got intermediate response:\n%s\n",
             response);
    
    //here the response should be sent to the server, and the server should
    //respond with a challenge
    //to make the example simpler (and non-functional) we hardcode a challenge
    const gchar* server_challenge = "some challenge";
    
    //submit the challenge to the plugin
    GSignondSessionData* data = gsignond_dictionary_new();
    gsignond_dictionary_set_string(data, "ChallengeBase64", server_challenge);
    gsignond_plugin_request(plugin, data);
    gsignond_dictionary_unref(data);
}

// print an error and exit the mainloop
static void error_callback(GSignondPlugin* plugin, GError* error,
                     gpointer user_data)
{
    g_print("Got an error: %s\n", error->message);
}

static void anonymous_authorization(gpointer plugin)
{
    GSignondSessionData* data = gsignond_dictionary_new();

    //fill in necessary data
    gsignond_dictionary_set_string(data, "AnonymousToken", 
                                   "megauser@example.com");

    //start the authorization
    //any further processing happens in signal callbacks
    gsignond_plugin_request_initial(plugin, data, NULL, "ANONYMOUS");
    gsignond_dictionary_unref(data);
}

static void plain_authorization(gpointer plugin)
{
    GSignondSessionData* data = gsignond_dictionary_new();

    //fill in necessary data
    gsignond_session_data_set_username(data, "megauser@example.com");
    gsignond_session_data_set_secret(data, "megapassword");

    //start the authorization
    //any further processing happens in signal callbacks
    gsignond_plugin_request_initial(plugin, data, NULL, "PLAIN");
    gsignond_dictionary_unref(data);
}

static void cram_md5_authorization(gpointer plugin)
{
    GSignondSessionData* data = gsignond_dictionary_new();

    //fill in necessary data
    gsignond_session_data_set_username(data, "megauser@example.com");
    gsignond_session_data_set_secret(data, "megapassword");
    //initial server challenge, for simplicty it's hardcoded
    gsignond_dictionary_set_string(data, "ChallengeBase64", "some challenge");    

    //start the authorization
    //any further processing happens in signal callbacks
    gsignond_plugin_request_initial(plugin, data, NULL, "CRAM-MD5");
    gsignond_dictionary_unref(data);
}

static void digest_md5_authorization(gpointer plugin)
{
    GSignondSessionData* data = gsignond_dictionary_new();

    //fill in necessary data
    gsignond_dictionary_set_string(data, "Service", "megaservice");
    gsignond_dictionary_set_string(data, "Hostname", "megahostname");
    GSequence* allowed_realms_s = gsignond_copy_array_to_sequence(allowed_realms);
    gsignond_session_data_set_allowed_realms(data, allowed_realms_s);
    g_sequence_free(allowed_realms_s);
    gsignond_session_data_set_username(data, "megauser@example.com");
    gsignond_session_data_set_secret(data, "megapassword");
    //initial server challenge, for simplicty it's hardcoded
    gsignond_dictionary_set_string(data, "ChallengeBase64", "some challenge");    

    //start the authorization
    //any further processing happens in signal callbacks
    gsignond_plugin_request_initial(plugin, data, NULL, "DIGEST-MD5");
    gsignond_dictionary_unref(data);
}


static void scram_sha1_authorization(gpointer plugin)
{
    GSignondSessionData* data = gsignond_dictionary_new();

    //fill in necessary data
    gsignond_session_data_set_username(data, "megauser@example.com");
    gsignond_session_data_set_secret(data, "megapassword");

    //initial server challenge, for simplicty it's hardcoded
    gsignond_dictionary_set_string(data, "ChallengeBase64", "some challenge");    

    //start the authorization
    //any further processing happens in signal callbacks
    gsignond_plugin_request_initial(plugin, data, NULL, "SCRAM-SHA-1");
    gsignond_dictionary_unref(data);
}


int main (void)
{
#if !GLIB_CHECK_VERSION (2, 36, 0)
    g_type_init ();
#endif

    gpointer plugin = g_object_new(gsignond_sasl_plugin_get_type(), NULL);

    //connect to various signals of the plugin object
    g_signal_connect(plugin, "response-final", G_CALLBACK(final_response_callback), NULL);
    g_signal_connect(plugin, "response", G_CALLBACK(response_callback), NULL);
    g_signal_connect(plugin, "error", G_CALLBACK(error_callback), NULL);

    //how to use various authorization mechanisms
    anonymous_authorization(plugin);
    plain_authorization(plugin);
    cram_md5_authorization(plugin);
    digest_md5_authorization(plugin);
    scram_sha1_authorization(plugin);
        
    g_object_unref(plugin);
    
    return 0;
}
