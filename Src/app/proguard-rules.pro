# Add project specific ProGuard rules here.

# Keep framework API signatures used via reflection in collectors.
# Although Android framework classes are not obfuscated by app shrinking,
# explicit keep rules make reflective dependencies clear and stable.
-keep class android.os.SELinux {
    public static boolean isSELinuxEnabled();
    public static boolean isSELinuxEnforced();
}

-keep class android.os.Build { *; }
-keep class android.os.Build$VERSION { *; }

-keep class android.content.pm.PackageManager { *; }
-keep class android.content.pm.PackageInfo { *; }
-keep class android.content.pm.ApplicationInfo { *; }
