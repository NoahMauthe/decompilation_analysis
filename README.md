# Decompilation Failure Analysis

The code in this repository was used to perform a large scale analysis on Android applications presented in the paper *"A Large-Scale Empirical Study of Android App Decompilation"*.


## Build

Our work is split over multiple repositories to make it easier to manage, but if you are simply looking to recompute our results or perform your own study using our tools, we provide a [singularity](https://sylabs.io/) container definition file that can be built using just two lines code:

    wget https://raw.githubusercontent.com/NoahMauthe/decompilation_analysis/master/decompilation_analysis.def
    singularity build decompilation_analysis.sif decompilation_analysis.def

## [Crawler](https://github.com/NoahMauthe/apk_crawler)

To establish the dataset we ran our tools on, we created a crawler that is able to retrieve apk files from F-Droid and, when given credentials, the Google Play Store.
As we wanted to have as much expandability as possible, the crawler itself is just a simple script and everything store specific is implemented in our [APIs](https://github.com/NoahMauthe/APIs).

Since the crawler was not the main focus of the work, the Google Play API we created is a heavily modified version of [https://github.com/NoMore201/googleplay-api](https://github.com/NoMore201/googleplay-api) to accomodate the needs of our analysis.

## Decompilation analysis

Our analysis tool, contained in this repository, runs four different decompilers on each application, and is capable of checking for the presence of certain  packers that might hinder decompilation as well.

Additionally, we perform a matching of the failures reported by our decompilers so we get an idea whether there were some methods that failed decompilation with all of the decompilers.

## Tools used

In order to achieve our analysis goal, we relied on a number of open-source tools:

###Decompilers

As mentioned before, we used four different decompilers:

* [CFR](https://www.benf.org/other/cfr)
* [jadx](https://github.com/skylot/jadx)
* [fernflower](https://github.com/JetBrains/intellij-community/tree/master/plugins/java-decompiler/engine)
* [procyon](https://bitbucket.org/mstrobel/procyon)

For CFR and procyon, we created our own versions that keep all of the functionality, but change the output so it is easier to process in an automated fashion.
They can be found at [https://github.com/NoahMauthe/cfr](https://github.com/NoahMauthe/cfr) and [https://github.com/NoahMauthe/procyon](https://github.com/NoahMauthe/procyon).

### Dex-tools

Additionally, we employed multiple dex-tools for various reasons:

* [APKiD](https://github.com/rednaga/APKiD) - A fingerprinting tool that checks for the presence of packers.
* [apkanalyzer](https://developer.android.com/studio/command-line/apkanalyzer) - A part of the android command line tools, it allowed us to extract method sizes and signatures.
* [dex2jar](https://github.com/pxb1988/dex2jar) - As the name implies, dex2jar is a conversion tool that enabled the use of our  three java decompilers.
