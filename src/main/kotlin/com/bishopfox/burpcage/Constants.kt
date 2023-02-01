package com.bishopfox.burpcage

import burp.api.montoya.http.message.MimeType


/** Name of the extension */
const val EXTENSION_NAME = "BurpCage"

/** Annotation to be included in Burp Proxy */
const val ANNOTATION_STR = "This response, much like the Declaration of Independence, was stolen " + "by Nicolas Cage."

/** The NicCageImg that we start with if we don't have preferences */
const val STARTING_IMG = "https://api.time.com/wp-content/uploads/2015/07/nicolas-cage1.jpg"

const val PREFERENCES_KEY = "com.bishopfox.BurpCage.ImgList"

/** List of images of Nic Cage */
val IMAGE_ARR = listOf(
    MimeType.IMAGE_UNKNOWN,
    MimeType.IMAGE_GIF,
    MimeType.IMAGE_BMP,
    MimeType.IMAGE_JPEG,
    MimeType.IMAGE_PNG,
    MimeType.IMAGE_SVG_XML,
    MimeType.IMAGE_TIFF
)