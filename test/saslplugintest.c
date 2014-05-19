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

#include <check.h>
#include <stdlib.h>
#include "gsignond-sasl-plugin.h"
#include <gsignond/gsignond-session-data.h>
#include <gsignond/gsignond-plugin-interface.h>
#include <gsignond/gsignond-error.h>
#include <gsignond/gsignond-config.h>
#include <gsignond/gsignond-utils.h>

static const gchar *allowed_realms[] = {
    "microhostname",
    "megahostname",
    NULL
};

static void check_plugin(GSignondPlugin* plugin)
{
    gchar* type;
    gchar** mechanisms;

    fail_if(plugin == NULL);
    
    g_object_get(plugin, "type", &type, "mechanisms", &mechanisms, NULL);
    
    fail_unless(g_strcmp0(type, "sasl") == 0);
    fail_unless(g_strcmp0(mechanisms[0], "ANONYMOUS") == 0);
    
    g_free(type);
    g_strfreev(mechanisms);
}

START_TEST (test_saslplugin_create)
{
    g_print("Starting test_saslplugin_create\n");
    gpointer plugin;
    
    plugin = g_object_new(GSIGNOND_TYPE_SASL_PLUGIN, NULL);
    check_plugin(plugin);
    g_object_unref(plugin);
}
END_TEST

static void response_callback(GSignondPlugin* plugin, GSignondSessionData* result,
                     gpointer user_data)
{
    GSignondSessionData** user_data_p = user_data;
    *user_data_p = gsignond_dictionary_copy(result);
}

static void error_callback(GSignondPlugin* plugin, GError* error,
                     gpointer user_data)
{
    GError** user_data_p = user_data;
    *user_data_p = g_error_copy(error);
}


START_TEST (test_saslplugin_request_anonymous)
{
    g_print("Starting test_saslplugin_request_anonymous\n");

    gpointer plugin;
    
    plugin = g_object_new(GSIGNOND_TYPE_SASL_PLUGIN, NULL);
    fail_if(plugin == NULL);

    GSignondSessionData* result = NULL;
    GSignondSessionData* result_final = NULL;
    GError* error = NULL;

    g_signal_connect(plugin, "response-final", G_CALLBACK(response_callback), &result_final);
    g_signal_connect(plugin, "response", 
                     G_CALLBACK(response_callback), &result);
    g_signal_connect(plugin, "error", G_CALLBACK(error_callback), &error);

    GSignondSessionData* data = gsignond_dictionary_new();

    gsignond_plugin_request_initial(plugin, data, NULL, "ANONYMOUS");

    fail_if(result != NULL);    
    fail_if(result_final != NULL);
    fail_if(error == NULL);
    fail_unless(g_error_matches(error, GSIGNOND_ERROR, 
                                GSIGNOND_ERROR_NOT_AUTHORIZED));
    g_error_free(error);
    error = NULL;
    
    gsignond_dictionary_set_string(data, "AnonymousToken", 
                                   "megauser@example.com");
    gsignond_plugin_request_initial(plugin, data, NULL, "ANONYMOUS");
    fail_if(result != NULL);    
    fail_if(result_final == NULL);
    fail_if(error != NULL);

    const gchar* response = gsignond_dictionary_get_string(result_final,
                                                           "ResponseBase64");
    char *response_decoded;
    size_t response_decoded_len;
    fail_if(gsasl_base64_from(response, strlen(response), &response_decoded,
                              &response_decoded_len) != GSASL_OK);
    fail_if(strncmp("megauser@example.com", response_decoded, strlen("megauser@example.com")) != 0);
    free(response_decoded);
    
     gsignond_dictionary_unref(result_final);
    result_final = NULL;
    
     gsignond_dictionary_unref(data);
    g_object_unref(plugin);
}
END_TEST

START_TEST (test_saslplugin_request_plain)
{
    g_print("Starting test_saslplugin_request_plain\n");
    gpointer plugin;
    
    plugin = g_object_new(GSIGNOND_TYPE_SASL_PLUGIN, NULL);
    fail_if(plugin == NULL);

    GSignondSessionData* result = NULL;
    GSignondSessionData* result_final = NULL;
    GError* error = NULL;

    g_signal_connect(plugin, "response-final", G_CALLBACK(response_callback), &result_final);
    g_signal_connect(plugin, "response", 
                     G_CALLBACK(response_callback), &result);
    g_signal_connect(plugin, "error", G_CALLBACK(error_callback), &error);

    GSignondSessionData* data = gsignond_dictionary_new();

    gsignond_session_data_set_username(data, "megauser@example.com");
    gsignond_session_data_set_secret(data, "megapassword");

    gsignond_plugin_request_initial(plugin, data, NULL, "PLAIN");

    fail_if(result != NULL);    
    fail_if(result_final == NULL);
    fail_if(error != NULL);

    const gchar* response = gsignond_dictionary_get_string(result_final,
                                                           "ResponseBase64");
    char *response_decoded;
    size_t response_decoded_len;
    fail_if(gsasl_base64_from(response, strlen(response), &response_decoded,
                              &response_decoded_len) != GSASL_OK);
    fail_if(strncmp("megauser@example.com", response_decoded+1, strlen("megauser@example.com")) != 0);
    fail_if(strncmp("megapassword", response_decoded+22, strlen("megapassword")) != 0);
    free(response_decoded);
    
    gsignond_dictionary_unref(result_final);
    result_final = NULL;
    
     gsignond_dictionary_unref(data);
    g_object_unref(plugin);
}
END_TEST

START_TEST (test_saslplugin_request_digest_md5)
{
    g_print("Starting test_saslplugin_request_digest_md5\n");
    gpointer plugin;
    Gsasl *gsasl_context;
    Gsasl_session *gsasl_session;    
    
    plugin = g_object_new(GSIGNOND_TYPE_SASL_PLUGIN, NULL);
    fail_if(plugin == NULL);
    
    fail_if (gsasl_init (&gsasl_context) != GSASL_OK);
    fail_if (gsasl_server_start (gsasl_context, 
                                 "DIGEST-MD5", 
                                 &gsasl_session) != GSASL_OK);
    
    GSignondSessionData* result = NULL;
    GSignondSessionData* result_final = NULL;
    GError* error = NULL;

    g_signal_connect(plugin, "response-final", G_CALLBACK(response_callback), &result_final);
    g_signal_connect(plugin, "response", 
                     G_CALLBACK(response_callback), &result);
    g_signal_connect(plugin, "error", G_CALLBACK(error_callback), &error);

    GSignondSessionData* data = gsignond_dictionary_new();

    char* server_challenge;
    fail_if(gsasl_step64(gsasl_session, "", &server_challenge) != GSASL_NEEDS_MORE);
    
    gsignond_dictionary_set_string(data, "ChallengeBase64", server_challenge);
    free(server_challenge);
    gsignond_dictionary_set_string(data, "Service", "megaservice");
    gsignond_dictionary_set_string(data, "Hostname", "megahostname");
    GSequence *seq = gsignond_copy_array_to_sequence(allowed_realms);
    gsignond_session_data_set_allowed_realms(data, seq);
    g_sequence_free(seq);
    gsignond_session_data_set_username(data, "megauser@example.com");
    gsignond_session_data_set_secret(data, "megapassword");
   
    gsignond_plugin_request_initial(plugin, data, NULL, "DIGEST-MD5");

    fail_if(result == NULL);    
    fail_if(result_final != NULL);
    fail_if(error != NULL);

    gsasl_property_set(gsasl_session, GSASL_PASSWORD, "megapassword");

    fail_if(gsasl_step64(gsasl_session, 
                         gsignond_dictionary_get_string(result,
                                                        "ResponseBase64"), 
                         &server_challenge) != GSASL_OK);
     gsignond_dictionary_unref(result);
    result = NULL;

    gsignond_dictionary_set_string(data, "ChallengeBase64", server_challenge);
    free(server_challenge);
    gsignond_plugin_request(plugin, data);

    fail_if(result != NULL);    
    fail_if(result_final == NULL);
    fail_if(error != NULL);

    fail_if(strlen(gsignond_dictionary_get_string(result_final,
                                                           "ResponseBase64")) > 0);
     gsignond_dictionary_unref(result_final);
    result_final = NULL;    
    
    gsasl_finish(gsasl_session);
    gsasl_done(gsasl_context);
     gsignond_dictionary_unref(data);
    g_object_unref(plugin);
}
END_TEST

START_TEST (test_saslplugin_request_cram_md5)
{
    g_print("Starting test_saslplugin_request_cram_md5\n");
    gpointer plugin;
    Gsasl *gsasl_context;
    Gsasl_session *gsasl_session;    
    
    plugin = g_object_new(GSIGNOND_TYPE_SASL_PLUGIN, NULL);
    fail_if(plugin == NULL);
    
    fail_if (gsasl_init (&gsasl_context) != GSASL_OK);
    fail_if (gsasl_server_start (gsasl_context, 
                                 "CRAM-MD5", 
                                 &gsasl_session) != GSASL_OK);
    
    GSignondSessionData* result = NULL;
    GSignondSessionData* result_final = NULL;
    GError* error = NULL;

    g_signal_connect(plugin, "response-final", G_CALLBACK(response_callback), &result_final);
    g_signal_connect(plugin, "response", 
                     G_CALLBACK(response_callback), &result);
    g_signal_connect(plugin, "error", G_CALLBACK(error_callback), &error);

    GSignondSessionData* data = gsignond_dictionary_new();

    char* server_challenge;
    fail_if(gsasl_step64(gsasl_session, "", &server_challenge) != GSASL_NEEDS_MORE);

    gsignond_dictionary_set_string(data, "ChallengeBase64", server_challenge);
    free(server_challenge);
    gsignond_session_data_set_username(data, "megauser@example.com");
    gsignond_session_data_set_secret(data, "megapassword");
    
    gsignond_plugin_request_initial(plugin, data, NULL, "CRAM-MD5");

    fail_if(result != NULL);    
    fail_if(result_final == NULL);
    fail_if(error != NULL);

    const gchar* response = gsignond_dictionary_get_string(result_final,
                                                           "ResponseBase64");
    char *response_decoded;
    size_t response_decoded_len;
    fail_if(gsasl_base64_from(response, strlen(response), &response_decoded,
                              &response_decoded_len) != GSASL_OK);
    fail_if(strncmp(response_decoded, "megauser@example.com", strlen("megauser@example.com")) != 0);
    free(response_decoded);    

     gsignond_dictionary_unref(result_final);
    result_final = NULL;    
    
    gsasl_finish(gsasl_session);
    gsasl_done(gsasl_context);
     gsignond_dictionary_unref(data);
    g_object_unref(plugin);
}
END_TEST

START_TEST (test_saslplugin_request_scram_sha_1)
{
    g_print("Starting test_saslplugin_request_scram_sha_1\n");
    gpointer plugin;
    Gsasl *gsasl_context;
    Gsasl_session *gsasl_session;    
    
    plugin = g_object_new(GSIGNOND_TYPE_SASL_PLUGIN, NULL);
    fail_if(plugin == NULL);
    
    fail_if (gsasl_init (&gsasl_context) != GSASL_OK);
    fail_if (gsasl_server_start (gsasl_context, 
                                 "SCRAM-SHA-1", 
                                 &gsasl_session) != GSASL_OK);
    
    GSignondSessionData* result = NULL;
    GSignondSessionData* result_final = NULL;
    GError* error = NULL;

    g_signal_connect(plugin, "response-final", G_CALLBACK(response_callback), &result_final);
    g_signal_connect(plugin, "response", 
                     G_CALLBACK(response_callback), &result);
    g_signal_connect(plugin, "error", G_CALLBACK(error_callback), &error);

    GSignondSessionData* data = gsignond_dictionary_new();

    char* server_challenge;
    fail_if(gsasl_step64(gsasl_session, "", &server_challenge) != GSASL_NEEDS_MORE);
    
    gsignond_dictionary_set_string(data, "ChallengeBase64", server_challenge);
    free(server_challenge);
    gsignond_session_data_set_username(data, "megauser@example.com");
    gsignond_session_data_set_secret(data, "megapassword");
   
    gsignond_plugin_request_initial(plugin, data, NULL, "SCRAM-SHA-1");

    fail_if(result == NULL);    
    fail_if(result_final != NULL);
    fail_if(error != NULL);
    gsasl_property_set(gsasl_session, GSASL_PASSWORD, "megapassword");
    fail_if (gsasl_step64(gsasl_session, 
                          gsignond_dictionary_get_string(result,
                                                         "ResponseBase64"), 
                          &server_challenge) != GSASL_NEEDS_MORE);
     gsignond_dictionary_unref(result);
    result = NULL;

    gsignond_dictionary_set_string(data, "ChallengeBase64", server_challenge);
    free(server_challenge);
    gsignond_plugin_request(plugin, data);

    fail_if(result == NULL);    
    fail_if(result_final != NULL);
    fail_if(error != NULL);

    fail_if (gsasl_step64(gsasl_session, 
                          gsignond_dictionary_get_string(result,
                                                         "ResponseBase64"), 
                          &server_challenge) != GSASL_OK);
     gsignond_dictionary_unref(result);
    result = NULL;

    gsignond_dictionary_set_string(data, "ChallengeBase64", server_challenge);
    free(server_challenge);
    gsignond_plugin_request(plugin, data);

    fail_if(result != NULL);    
    fail_if(result_final == NULL);
    fail_if(error != NULL);
    
    fail_if(strlen(gsignond_dictionary_get_string(result_final,
                                                           "ResponseBase64")) > 0);
     gsignond_dictionary_unref(result_final);
    result_final = NULL;    
    
    gsasl_finish(gsasl_session);
    gsasl_done(gsasl_context);
    gsignond_dictionary_unref(data);
    g_object_unref(plugin);
}
END_TEST

Suite* saslplugin_suite (void)
{
    Suite *s = suite_create ("SASL plugin");
    
    /* Core test case */
    TCase *tc_core = tcase_create ("Tests");
    tcase_add_test (tc_core, test_saslplugin_create);
    tcase_add_test (tc_core, test_saslplugin_request_anonymous);
    tcase_add_test (tc_core, test_saslplugin_request_plain);
    tcase_add_test (tc_core, test_saslplugin_request_digest_md5);
    tcase_add_test (tc_core, test_saslplugin_request_cram_md5);
    tcase_add_test (tc_core, test_saslplugin_request_scram_sha_1);
    suite_add_tcase (s, tc_core);
    return s;
}

int main (void)
{
    int number_failed;
    
#if !GLIB_CHECK_VERSION (2, 36, 0)
    g_type_init ();
#endif
    
    Suite *s = saslplugin_suite();
    SRunner *sr = srunner_create(s);
    srunner_run_all(sr, CK_NORMAL);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);
    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
  
