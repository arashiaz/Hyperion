plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "ir.hyperion.app"
    compileSdk = 34

    defaultConfig {
        applicationId = "ir.hyperion.app"
        // 26 rather than 24: java.util.Base64 and java.time are used directly so
        // that the crypto stays in plain JVM code and can be unit-tested without
        // Robolectric or android.jar stubs.
        minSdk = 26
        targetSdk = 34
        versionCode = 1
        versionName = "0.1.0"
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro",
            )
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    kotlinOptions {
        jvmTarget = "17"
    }

    // The cross-language vectors live at the repository root next to the Python
    // core that generates them.  Exposing them as test resources means the JVM
    // unit tests fail if the Kotlin side drifts from the Python side.
    sourceSets.getByName("test").resources.srcDir("$rootDir/../vectors")

    testOptions {
        unitTests.isReturnDefaultValues = false
    }
}

dependencies {
    implementation("androidx.core:core-ktx:1.13.1")
    implementation("androidx.appcompat:appcompat:1.7.0")
    implementation("androidx.constraintlayout:constraintlayout:2.1.4")
    testImplementation("junit:junit:4.13.2")
}
