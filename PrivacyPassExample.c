#include "PrivacyPassExample.h"
#include "blind_rsa.h"

jlong Java_PrivacyPassExample_brsa_1context_1new(JNIEnv *env, jobject obj) {
    BRSAContext *context = (BRSAContext *)malloc(sizeof(BRSAContext));
    return (jlong)context;
}

jlong Java_PrivacyPassExample_brsa_1secret_1key_1new(JNIEnv *env, jobject obj) {
    BRSASecretKey *secret_key = (BRSASecretKey *)malloc(sizeof(BRSASecretKey));
    return (jlong)secret_key;
}

jlong Java_PrivacyPassExample_brsa_1public_1key_1new(JNIEnv *env, jobject obj) {
    BRSAPublicKey *public_key = (BRSAPublicKey *)malloc(sizeof(BRSAPublicKey));
    return (jlong)public_key;
}

jlong Java_PrivacyPassExample_brsa_1blind_1message_1new(JNIEnv *env, jobject obj) {
    BRSABlindMessage *blind_msg = (BRSABlindMessage *)malloc(sizeof(BRSABlindMessage));
    return (jlong)blind_msg;
}

jlong Java_PrivacyPassExample_brsa_1blinding_1secret_1new(JNIEnv *env, jobject obj) {
    BRSABlindingSecret *blinding_secret = (BRSABlindingSecret *)malloc(sizeof(BRSABlindingSecret));
    return (jlong)blinding_secret;
}

jlong Java_PrivacyPassExample_brsa_1blind_1signature_1new(JNIEnv *env, jobject obj) {
    BRSABlindSignature *blind_sig = (BRSABlindSignature *)malloc(sizeof(BRSABlindSignature));
    return (jlong)blind_sig;
}

jlong Java_PrivacyPassExample_brsa_1signature_1new(JNIEnv *env, jobject obj) {
    BRSASignature *sig = (BRSASignature *)malloc(sizeof(BRSASignature));
    return (jlong)sig;
}

void Java_PrivacyPassExample_brsa_1context_1free(JNIEnv *env, jobject obj, jlong ptr) {
    free((void *)ptr);
}

void Java_PrivacyPassExample_brsa_1secret_1key_1free(JNIEnv *env, jobject obj, jlong ptr) {
    free((void *)ptr);
}

void Java_PrivacyPassExample_brsa_1public_1key_1free(JNIEnv *env, jobject obj, jlong ptr) {
    free((void *)ptr);
}

void Java_PrivacyPassExample_brsa_1blind_1message_1free(JNIEnv *env, jobject obj, jlong ptr) {
    free((void *)ptr);
}

void Java_PrivacyPassExample_brsa_1blinding_1secret_1free(JNIEnv *env, jobject obj, jlong ptr) {
    free((void *)ptr);
}

void Java_PrivacyPassExample_brsa_1blind_1signature_1free(JNIEnv *env, jobject obj, jlong ptr) {
    free((void *)ptr);
}

void Java_PrivacyPassExample_brsa_1signature_1free(JNIEnv *env, jobject obj, jlong ptr) {
    free((void *)ptr);
}

jint Java_PrivacyPassExample_brsa_1publickey_1import_1spki(JNIEnv *env, jobject obj, jlong ctx_ptr, jlong public_key_ptr, jbyteArray spki) {
    jboolean is_copy;
    jbyte* spki_ptr = (*env)->GetByteArrayElements(env, spki, &is_copy);
    jsize spki_len = (*env)->GetArrayLength(env, spki);

    int result = brsa_publickey_import_spki((BRSAContext *)ctx_ptr, (BRSAPublicKey *)public_key_ptr, (uint8_t *)spki_ptr, (size_t)spki_len);
    return (jint)result;
}

jint Java_PrivacyPassExample_brsa_1blind_1signature_1import(JNIEnv *env, jobject obj, jlong ctx_ptr, jlong blind_sig_ptr, jbyteArray encoded_blind_sig) {
    jboolean is_copy;
    jbyte* encoded_blind_sig_ptr = (*env)->GetByteArrayElements(env, encoded_blind_sig, &is_copy);
    jsize encoded_blind_sig_len = (*env)->GetArrayLength(env, encoded_blind_sig);

    int result = brsa_blind_signature_import((BRSAContext *)ctx_ptr, (BRSABlindSignature *)blind_sig_ptr, (uint8_t *)encoded_blind_sig_ptr, (size_t)encoded_blind_sig_len);
    return (jint)result;
}

jbyteArray Java_PrivacyPassExample_brsa_1blind_1message_1copy(JNIEnv *env, jobject obj, jlong blind_msg_ptr) {
    BRSABlindMessage *blind_msg = (BRSABlindMessage *)blind_msg_ptr;
    jbyteArray byte_array = (*env)->NewByteArray(env, blind_msg->blind_message_len);
    (*env)->SetByteArrayRegion(env, byte_array, 0, blind_msg->blind_message_len, (const jbyte*)blind_msg->blind_message);
    return byte_array;
}

jbyteArray Java_PrivacyPassExample_brsa_1signature_1copy(JNIEnv *env, jobject obj, jlong sig_ptr) {
    BRSASignature *sig = (BRSASignature *)sig_ptr;
    jbyteArray byte_array = (*env)->NewByteArray(env, sig->sig_len);
    (*env)->SetByteArrayRegion(env, byte_array, 0, sig->sig_len, (const jbyte*)sig->sig);
    return byte_array;
}

void Java_PrivacyPassExample_brsa_1context_1init(JNIEnv *env, jobject obj, jlong ctx_ptr) {
    brsa_context_init_default((BRSAContext *)ctx_ptr);
}

jint Java_PrivacyPassExample_brsa_1keygen(JNIEnv *env, jobject obj, jlong secret_key_ptr, jlong public_key_ptr, jint size) {
    return (jint)brsa_keypair_generate((BRSASecretKey *)secret_key_ptr, (BRSAPublicKey *)public_key_ptr, (int)size);
}

jint Java_PrivacyPassExample_brsa_1blind_1wrapper(JNIEnv *env, jobject obj, jlong ctx_ptr, jlong blind_msg_ptr, jlong blinding_secret_ptr, jlong public_key_ptr, jbyteArray msg) {
    jboolean is_copy;
    jbyte* msg_ptr = (*env)->GetByteArrayElements(env, msg, &is_copy);
    jsize msg_len = (*env)->GetArrayLength(env, msg);

    int result = brsa_blind((BRSAContext *)ctx_ptr, (BRSABlindMessage *)blind_msg_ptr, (BRSABlindingSecret *)blinding_secret_ptr, (BRSAPublicKey *)public_key_ptr, (uint8_t *)msg_ptr, (size_t)msg_len);
    return (jint)result;
}

jint Java_PrivacyPassExample_brsa_1blind_1sign_1wrapper(JNIEnv *env, jobject obj, jlong ctx_ptr, jlong blind_sig_ptr, jlong secret_key_ptr, jlong blind_msg_ptr) {
    int result = brsa_blind_sign((BRSAContext *)ctx_ptr, (BRSABlindSignature *)blind_sig_ptr, (BRSASecretKey *)secret_key_ptr, (BRSABlindMessage *)blind_msg_ptr);
    return (jint)result;
}

jint Java_PrivacyPassExample_brsa_1finalize_1wrapper(JNIEnv *env, jobject obj, jlong ctx_ptr, jlong sig_ptr, jlong blind_sig_ptr, jlong blinding_secret_ptr, jlong public_key_ptr, jbyteArray msg) {
    jboolean is_copy;
    jbyte* msg_ptr = (*env)->GetByteArrayElements(env, msg, &is_copy);
    jsize msg_len = (*env)->GetArrayLength(env, msg);

    int result = brsa_finalize((BRSAContext *)ctx_ptr, (BRSASignature *)sig_ptr, (BRSABlindSignature *)blind_sig_ptr, (BRSABlindingSecret *)blinding_secret_ptr, (BRSAPublicKey *)public_key_ptr, (uint8_t *)msg_ptr, (size_t)msg_len);
    return result;
}

jint Java_PrivacyPassExample_brsa_1verify(JNIEnv *env, jobject obj, jlong ctx_ptr, jlong sig_ptr, jlong public_key_ptr, jbyteArray msg) {
    jboolean is_copy;
    jbyte* msg_ptr = (*env)->GetByteArrayElements(env, msg, &is_copy);
    jsize msg_len = (*env)->GetArrayLength(env, msg);

    int result = brsa_verify((BRSAContext *)ctx_ptr, (BRSASignature *)sig_ptr, (BRSAPublicKey *)public_key_ptr, (uint8_t *)msg_ptr, (size_t)msg_len);
    return (jint)result;
}