plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.plugin.compose")
}
android {
    namespace = "dev.guardian.app"
    compileSdk = 37
    defaultConfig {
        applicationId = "dev.guardian.app"
        minSdk = 29
        targetSdk = 36
        versionCode = 1
        versionName = "0.1-dev"
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }
    buildTypes { release { isMinifyEnabled = true; isShrinkResources = true } }
    compileOptions { sourceCompatibility = JavaVersion.VERSION_17; targetCompatibility = JavaVersion.VERSION_17 }
    buildFeatures { compose = true }
    // AGP 9.5.1 lint's BidiSpoofing check loops in Kotlin PSI on this project.
    // The equivalent source scan runs in scripts/check_bidi.py and CI.
    lint { disable += "BidiSpoofing" }
}
dependencies {
    implementation(project(":core:crypto"))
    implementation(project(":feature:generator"))
    implementation(project(":feature:authenticator"))
    implementation(platform("androidx.compose:compose-bom:2026.09.00"))
    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.material3:material3")
    implementation("androidx.activity:activity-compose:1.13.0")
    implementation("androidx.core:core-ktx:1.19.1")
    androidTestImplementation("androidx.test.ext:junit:1.3.0")
    androidTestImplementation("androidx.test:core:1.7.0")
    androidTestImplementation("androidx.test:runner:1.7.0")
}
