/*

The MIT License (MIT)

Copyright (c) 2018  Dmitrii Kozhevin <kozhevin.dima@gmail.com>

Permission is hereby granted, free of charge, to any person obtaining a copy of this software
and associated documentation files (the “Software”), to deal in the Software without
restriction, including without limitation the rights to use, copy, modify, merge, publish,
distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the
Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or
substantial portions of the Software.

THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING
BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

 */

#include <jni.h>
#include <malloc.h>

#include "path_helper.h"
#include "unzip_helper.h"
#include "pkcs7_helper.h"

const char *RELEASE_SIGN = "B191465A93644BCFC35B3B0571C9F112";

void ByteToHexStr(const char *source, char *dest, int sourceLen) {
    short i;
    char highByte, lowByte;

    for (i = 0; i < sourceLen; i++) {
        highByte = source[i] >> 4;
        lowByte = source[i] & 0x0f;
        highByte += 0x30;

        if (highByte > 0x39) {
            dest[i * 2] = highByte + 0x07;
        } else {
            dest[i * 2] = highByte;
        }

        lowByte += 0x30;
        if (lowByte > 0x39) {
            dest[i * 2 + 1] = lowByte + 0x07;
        } else {
            dest[i * 2 + 1] = lowByte;
        }
    }
}

// byte数组转MD5字符串
jstring ToMd5(JNIEnv *env, jbyteArray source) {
    // MessageDigest类
    jclass classMessageDigest = (*env)->FindClass(env, "java/security/MessageDigest");
    // MessageDigest.getInstance()静态方法
    jmethodID midGetInstance = (*env)->GetStaticMethodID(env, classMessageDigest, "getInstance",
                                                         "(Ljava/lang/String;)Ljava/security/MessageDigest;");
    // MessageDigest object
    jobject objMessageDigest = (*env)->CallStaticObjectMethod(env, classMessageDigest,
                                                              midGetInstance,
                                                              (*env)->NewStringUTF(env, "md5"));

    // update方法，这个函数的返回值是void，写V
    jmethodID midUpdate = (*env)->GetMethodID(env, classMessageDigest, "update", "([B)V");
    (*env)->CallVoidMethod(env, objMessageDigest, midUpdate, source);

    // digest方法
    jmethodID midDigest = (*env)->GetMethodID(env, classMessageDigest, "digest", "()[B");
    jbyteArray objArraySign = (jbyteArray) (*env)->CallObjectMethod(env, objMessageDigest,
                                                                    midDigest);

    jsize intArrayLength = (*env)->GetArrayLength(env, objArraySign);
    jbyte *byte_array_elements = (*env)->GetByteArrayElements(env, objArraySign, NULL);
    size_t length = (size_t) intArrayLength * 2 + 1;
    char *char_result = (char *) malloc(length);
    memset(char_result, 0, length);

    // 将byte数组转换成16进制字符串，发现这里不用强转，jbyte和unsigned char应该字节数是一样的
    ByteToHexStr((const char *) byte_array_elements, char_result, intArrayLength);
    // 在末尾补\0
    *(char_result + intArrayLength * 2) = '\0';

    jstring stringResult = (*env)->NewStringUTF(env, char_result);
    // release
    (*env)->ReleaseByteArrayElements(env, objArraySign, byte_array_elements, JNI_ABORT);
    // 释放指针使用free
    free(char_result);
    (*env)->DeleteLocalRef(env, classMessageDigest);
    (*env)->DeleteLocalRef(env, objMessageDigest);

    return stringResult;
}

static jobject getApplication(JNIEnv *env) {
    jobject application = NULL;
    jclass activity_thread_clz = (*env)->FindClass(env, "android/app/ActivityThread");
    if (activity_thread_clz != NULL) {
        jmethodID currentApplication = (*env)->GetStaticMethodID(env,
                                                                 activity_thread_clz,
                                                                 "currentApplication",
                                                                 "()Landroid/app/Application;");
        if (currentApplication != NULL) {
            application = (*env)->CallStaticObjectMethod(env, activity_thread_clz,
                                                         currentApplication);
        } else {
            //           LOGE("Cannot find method: currentApplication() in ActivityThread.");
        }
        (*env)->DeleteLocalRef(env, activity_thread_clz);
    } else {
//        LOGE("Cannot find class: android.app.ActivityThread");
    }

    return application;
}

//获取应用签名
jstring loadSignature(JNIEnv *env, jobject context) {
    // 获得Context类
    jclass cls = (*env)->GetObjectClass(env, context);
    // 得到getPackageManager方法的ID
    jmethodID mid = (*env)->GetMethodID(env, cls, "getPackageManager",
                                        "()Landroid/content/pm/PackageManager;");

    // 获得应用包的管理器
    jobject pm = (*env)->CallObjectMethod(env, context, mid);

    // 得到getPackageName方法的ID
    mid = (*env)->GetMethodID(env, cls, "getPackageName", "()Ljava/lang/String;");
    // 获得当前应用包名
    jstring packageName = (jstring) (*env)->CallObjectMethod(env, context, mid);

    // 获得PackageManager类
    cls = (*env)->GetObjectClass(env, pm);
    // 得到getPackageInfo方法的ID
    mid = (*env)->GetMethodID(env, cls, "getPackageInfo",
                              "(Ljava/lang/String;I)Landroid/content/pm/PackageInfo;");
    // 获得应用包的信息
    jobject packageInfo = (*env)->CallObjectMethod(env, pm, mid, packageName,
                                                   0x40); //GET_SIGNATURES = 64;
    // 获得PackageInfo 类
    cls = (*env)->GetObjectClass(env, packageInfo);
    // 获得签名数组属性的ID
    jfieldID fid = (*env)->GetFieldID(env, cls, "signatures", "[Landroid/content/pm/Signature;");
    // 得到签名数组
    jobjectArray signatures = (jobjectArray) (*env)->GetObjectField(env, packageInfo, fid);
    // 得到签名
    jobject signature = (*env)->GetObjectArrayElement(env, signatures, 0);

    // 获得Signature类
    cls = (*env)->GetObjectClass(env, signature);
    // 得到toCharsString方法的ID
    mid = (*env)->GetMethodID(env, cls, "toByteArray", "()[B");
    // 返回当前应用签名信息
    jbyteArray signatureByteArray = (jbyteArray) (*env)->CallObjectMethod(env, signature, mid);

    return ToMd5(env, signatureByteArray);
}

JNIEXPORT jbyteArray JNICALL
Java_com_kozhevin_signverification_MainActivity_bytesFromJNI(JNIEnv *env, jobject this) {

    NSV_LOGI("pathHelperGetPath starts\n");
    char *path = pathHelperGetPath();
    NSV_LOGI("pathHelperGetPath finishes\n");

    if (!path) {
        return NULL;
    }
    NSV_LOGI("pathHelperGetPath result[%s]\n", path);
    NSV_LOGI("unzipHelperGetCertificateDetails starts\n");
    size_t len_in = 0;
    size_t len_out = 0;
    unsigned char *content = unzipHelperGetCertificateDetails(path, &len_in);
    NSV_LOGI("unzipHelperGetCertificateDetails finishes\n");
    if (!content) {
        free(path);
        return NULL;
    }
    // NSV_LOGI("content:%s\n",content);
    NSV_LOGI("pkcs7HelperGetSignature starts\n");

    unsigned char *res = pkcs7HelperGetSignature(content, len_in, &len_out);
    NSV_LOGI("pkcs7HelperGetSignature finishes\n");
    jbyteArray jbArray = NULL;
    if (NULL != res || len_out != 0) {
        jbArray = (*env)->NewByteArray(env, len_out);
        (*env)->SetByteArrayRegion(env, jbArray, 0, len_out, (jbyte *) res);
    }


    free(content);
    free(path);
    pkcs7HelperFree();
    jstring md5 = ToMd5(env, jbArray);
    const char *charAppSignature = (*env)->GetStringUTFChars(env, md5, NULL);
    NSV_LOGI("md5:%s\n", charAppSignature);
    return jbArray;
}

const char *getSignatureMD5(JNIEnv *env) {
    NSV_LOGI("pathHelperGetPath starts\n");
    char *path = pathHelperGetPath();
    NSV_LOGI("pathHelperGetPath finishes\n");

    if (!path) {
        return NULL;
    }
    NSV_LOGI("pathHelperGetPath result[%s]\n", path);
    NSV_LOGI("unzipHelperGetCertificateDetails starts\n");
    size_t len_in = 0;
    size_t len_out = 0;
    unsigned char *content = unzipHelperGetCertificateDetails(path, &len_in);
    NSV_LOGI("unzipHelperGetCertificateDetails finishes\n");
    if (!content) {
        free(path);
        return NULL;
    }
    // NSV_LOGI("content:%s\n",content);
    NSV_LOGI("pkcs7HelperGetSignature starts\n");

    unsigned char *res = pkcs7HelperGetSignature(content, len_in, &len_out);
    NSV_LOGI("pkcs7HelperGetSignature finishes\n");
    jbyteArray jbArray = NULL;
    if (NULL != res || len_out != 0) {
        jbArray = (*env)->NewByteArray(env, len_out);
        (*env)->SetByteArrayRegion(env, jbArray, 0, len_out, (jbyte *) res);
    }


    free(content);
    free(path);
    pkcs7HelperFree();
    jstring md5 = ToMd5(env, jbArray);
    const char *charAppSignature = (*env)->GetStringUTFChars(env, md5, NULL);
    NSV_LOGI("md5:%s\n", charAppSignature);
    return charAppSignature;
}

/**
 * 检查加载该so的应用的签名，与预置的签名是否一致
 */
static jboolean checkSignature(JNIEnv *env) {

    // 调用 getContext 方法得到 Context 对象
//    jobject appContext = getApplication(env);
//
//    if (appContext != NULL) {
//        jboolean signatureValid = checkSignature(
//                env, appContext);
//        return signatureValid;
//    }
    const char *a = getSignatureMD5(env);
    if (strcmp(a, RELEASE_SIGN) == 0) {
        return JNI_TRUE;
    }

    return JNI_FALSE;
}

/**
 * 加载 so 文件的时候，会触发 OnLoad
 * 检测失败，返回 -1，App 就会 Crash
 */
JNIEXPORT jint JNICALL
JNI_OnLoad(JavaVM *vm, void *reserved) {
    JNIEnv *env;
//    LOGI("  JNI_OnLoad  ");
    if ((*vm)->GetEnv(vm, (void **) (&env), JNI_VERSION_1_6) != JNI_OK) {
        return -1;
    }
//    LOGI("  start checkSignature  ");
    if (checkSignature(env) != JNI_TRUE) {
//        LOGI("  checkSignature = false ");
        // 检测不通过，返回 -1 就会使 App crash
        return -1;
    }

    return JNI_VERSION_1_6;
}



