-keepattributes Signature

# classes that will be serialized/deserialized over Gson
-keepclassmembers class com.wultra.android.sslpinning.model.** {
     <fields>;
}
# necessary for R8 fullMode
-keep,allowobfuscation class com.wultra.android.sslpinning.model.**