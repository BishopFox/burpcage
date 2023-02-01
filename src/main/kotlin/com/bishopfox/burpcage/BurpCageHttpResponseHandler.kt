package com.bishopfox.burpcage

import burp.api.montoya.MontoyaApi
import burp.api.montoya.core.Annotations
import burp.api.montoya.core.ByteArray
import burp.api.montoya.proxy.http.InterceptedResponse
import burp.api.montoya.proxy.http.ProxyResponseHandler
import burp.api.montoya.proxy.http.ProxyResponseReceivedAction
import burp.api.montoya.proxy.http.ProxyResponseToBeSentAction

/**
 * This is a class used for intercepting responses from a server.
 *
 * @param api Exposes the BurpCageHttpResponseHandler
 *      class to the Montoya Api
 */
class BurpCageHttpResponseHandler(private val api: MontoyaApi, private val nicCageImgList: NicCageImgList) :
    ProxyResponseHandler {

    /**
     * Helper function to determine if an HTTP response is an image MIME type
     *
     * @param interceptedResponse The intercepted response
     * @return True, if the MIME type is an image
     */
    private fun isImage(interceptedResponse: InterceptedResponse): Boolean {
        return interceptedResponse.inferredMimeType() in IMAGE_ARR || interceptedResponse.statedMimeType() in IMAGE_ARR
    }

    /**
     * According to the Montoya API, this function "is invoked when an HTTP
     * response is received in the Proxy". We can even control if the response
     * from the HTTP server should be intercepted by the Burp Proxy for the
     * burp user.
     *
     * @param interceptedResponse The response from the HTTP server that was
     * intercepted from Burp
     */
    override fun handleResponseReceived(interceptedResponse: InterceptedResponse?): ProxyResponseReceivedAction {
        /* This should never happen */
        if (interceptedResponse == null) {
            api.logging().logToError("Null response received. Dropping message.")
            return ProxyResponseReceivedAction.drop()
        }

        /* Condition to determine if we should ignore this response */
        if (this.api.scope().isInScope(interceptedResponse.initiatingRequest().url()) || !isImage(interceptedResponse)) {
            return ProxyResponseReceivedAction.continueWith(
                interceptedResponse
            )
        }

        /* Get the Nic Cage image */
        val nicCageImg: NicCageImg

        /* If there are no Nic Cage images, print an error and do the default proxy behavior */
        try {
            nicCageImg = nicCageImgList.getRandomImg()
        } catch (ex: IllegalStateException) {
            api.logging().logToError("Could not replace image, ignoring request: ${ex.message}")
            return ProxyResponseReceivedAction.continueWith(
                interceptedResponse
            )
        }

        /* Build the new response */
        val newResponse = interceptedResponse
            .withRemovedHeader("Content-Type")
            .withAddedHeader("Content-Type", nicCageImg.mimeType)
            .withBody(ByteArray.byteArray(*nicCageImg.imageBytes))

        /* Add to the annotations, to be viewed in the proxy pane */
        val newAnnotation = Annotations.annotations(ANNOTATION_STR)

        return ProxyResponseReceivedAction.continueWith(
            newResponse, newAnnotation
        )
    }

    /**
     * This function is invoked after the processing in Burp Proxy.
     *
     * @param interceptedResponse The response from the HTTP server that was
     * intercepted from Burp
     */
    override fun handleResponseToBeSent(interceptedResponse: InterceptedResponse?): ProxyResponseToBeSentAction {
        return ProxyResponseToBeSentAction.continueWith(interceptedResponse)
    }
}