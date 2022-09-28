package burp

import java.io.Serializable
import java.net.URL

class NicCageImg(val imgSrc: URL, val imgMime: String, val imgData: ByteArray): Serializable
{
    /**
     * Converts the NicCageImg to a string. This gets its image source.
     *
     * @return The string
     */
    override fun toString(): String
    {
        return imgSrc.toString()
    }
}