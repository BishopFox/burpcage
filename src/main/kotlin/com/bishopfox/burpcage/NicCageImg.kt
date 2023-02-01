package com.bishopfox.burpcage

import java.io.Serializable
import java.net.HttpURLConnection
import java.net.URL
import java.nio.file.Paths

/**
 * Creates a NicCageImg object, given an image URL. This will invoke an HTTP request, so you should
 * create each image in a new thread.
 *
 * @param imgSrc The image source
 */
class NicCageImg(private val imgSrc: String) : Serializable {
    val mimeType: String
    val imageBytes: ByteArray
    private val imageName: String

    /* Called when the NicCageImg class is constructed */
    init {/* We could get MalformedURLException, but let the caller handle it */
        val url = URL(imgSrc)

        /* We could get an IOException, but let the caller handle it */
        val httpConnection = url.openConnection() as HttpURLConnection
        mimeType = httpConnection.contentType
        imageBytes = httpConnection.inputStream.readBytes()

        /* Get the image name, to display in a human-readable format */
        imageName = Paths.get(url.path).fileName.toString()
    }

    /**
     * Converts the NicCageImg to a string. This gets its image source.
     *
     * @return The string
     */
    override fun toString(): String {
        return imageName
    }
}