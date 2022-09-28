package burp

/**
 * Instantiate a new HttpListener class with the Burp callbacks
 *
 * @param callbacks The Burp extender callbacks
 */
class HttpListener(private val callbacks: IBurpExtenderCallbacks) : IHttpListener
{
    /**
     * This method is invoked when an HTTP request is about to be issued, and
     * when an HTTP response has been received.
     *
     * @param toolFlag A flag indicating the Burp tool that issued the request.
     * Burp tool flags are defined in the
     * `IBurpExtenderCallbacks` interface.
     * @param messageIsRequest Flags whether the method is being invoked for a
     * request or response.
     * @param messageInfo Details of the request / response to be processed.
     * Extensions can call the setter methods on this object to update the
     * current message and so modify Burp's behavior.
     */
    override fun processHttpMessage(toolFlag: Int, messageIsRequest: Boolean, messageInfo: IHttpRequestResponse?)
    {
        /* The response could be null if we just have a request. */
        if (messageInfo?.response == null)
            return

        /* Get the Nicolas Cage image. If none exist, return. */
        val nicCageImg = getRandomImg() ?: return

        /* Get the response */
        val analyzedResponse = callbacks.helpers.analyzeResponse(messageInfo.response)

        /* Ignore non-image MIME types */
        if (analyzedResponse.statedMimeType !in REPLACE_CONTENT_TYPES)
            return

        /* Replace MIME type in the headers */
        val newHeaders = analyzedResponse.headers.map {
            return@map if (it.startsWith(CONTENT_TYPE, ignoreCase=true))
                "$CONTENT_TYPE: ${nicCageImg.imgMime}"
            else
                it
        }

        /* Build new response and send it */
        val newResponse = callbacks.helpers.buildHttpMessage(newHeaders, nicCageImg.imgData)
        messageInfo.response = newResponse
    }
}