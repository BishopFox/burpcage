package com.bishopfox.burpcage

import burp.api.montoya.BurpExtension
import burp.api.montoya.MontoyaApi

@Suppress("unused")
class BurpCageEntry : BurpExtension {
    /**
     * The entry point for the BurpCage extension.
     *
     * @param api An instance of the MontoyaApi
     */
    override fun initialize(api: MontoyaApi?) {
        /* Null safety check. Burp didn't add the sufficient annotations to its
         * MontoyaApi interface, so Kotlin thinks that it is possible for this
         * object to be null. This is just to make Kotlin happy.
         */
        if (api == null) {
            return
        }

        api.extension().setName(EXTENSION_NAME)
        api.logging().logToOutput("Loading $EXTENSION_NAME")

        /* Check if we have any persisted settings */
        val nicCageImgList: NicCageImgList
        if (api.persistence().preferences().getString(PREFERENCES_KEY) != null) {
            nicCageImgList = Utils.deserializeFromString(api.persistence().preferences().getString(PREFERENCES_KEY))
        } else {
            nicCageImgList = NicCageImgList()
            nicCageImgList.addImage(NicCageImg(STARTING_IMG))
        }

        /* Register proxy handler, and give it the MontoyaApi. */
        api.proxy().registerResponseHandler(BurpCageHttpResponseHandler(api, nicCageImgList))
        api.userInterface().registerSuiteTab(EXTENSION_NAME, BurpCageTab(api, nicCageImgList))
    }
}