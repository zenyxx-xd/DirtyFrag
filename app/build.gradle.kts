import java.util.Properties

plugins {
    id("com.android.application")
}

val signingProps = Properties().also {
    it.load(rootProject.file("signing.properties").inputStream())
}

android {
    namespace = "df.root"
    compileSdk = 36

    defaultConfig {
        applicationId = "df.root"
        minSdk = 32
        targetSdk = 36
        versionCode = 302
        versionName = "3.2"

        ndk {
            abiFilters += listOf("arm64-v8a")
        }
    }

    signingConfigs {
        create("release") {
            storeFile = file(signingProps.getProperty("KEYSTORE_FILE"))
            storePassword = signingProps.getProperty("KEYSTORE_PASSWORD")
            keyAlias = signingProps.getProperty("KEY_ALIAS")
            keyPassword = signingProps.getProperty("KEY_PASSWORD")
        }
    }

    buildTypes {
        debug {
            isDebuggable = true
            signingConfig = signingConfigs.getByName("debug")
        }
        release {
            signingConfig = signingConfigs.getByName("release")
            isMinifyEnabled = false
        }
    }

    applicationVariants.all {
        outputs.all {
            (this as com.android.build.gradle.internal.api.BaseVariantOutputImpl).outputFileName = "DFRoot_${versionName}.apk"
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_11
        targetCompatibility = JavaVersion.VERSION_11
    }

    lint {
        checkReleaseBuilds = false
    }

    buildFeatures {
        viewBinding = true
    }

    externalNativeBuild {
        cmake {
            path("src/main/jni/CMakeLists.txt")
        }
    }

    packaging {
        jniLibs {
            useLegacyPackaging = true
        }
    }
}

dependencies {
    implementation(libs.androidx.appcompat)
    implementation(libs.material)
    implementation(libs.androidx.constraintlayout)
    implementation(libs.androidx.preference)
}
