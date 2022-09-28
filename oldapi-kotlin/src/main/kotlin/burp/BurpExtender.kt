package burp

class BurpExtender: IBurpExtender
{
    /**
     * This method is invoked when the extension is loaded. It registers an
     * instance of the
     * `IBurpExtenderCallbacks` interface, providing methods that may
     * be invoked by the extension to perform various actions.
     *
     * @param callbacks An
     * `IBurpExtenderCallbacks` object.
     */
    override fun registerExtenderCallbacks(callbacks: IBurpExtenderCallbacks?)
    {
        /* This should never happen, but Burp hasn't annotated the callbacks variable with @NotNull */
        if (callbacks == null)
        {
            throw NullPointerException("Callbacks in extension entrypoint was null.")
        }

        /* Set extension name */
        callbacks.setExtensionName(EXTENSION_NAME)

        /* Create new HTTP listener and register it */
        val httpListener = HttpListener(callbacks)
        callbacks.registerHttpListener(httpListener)

        /* Finally, add a UI */
        val burpTab = NicCageBurpTab(callbacks)
        callbacks.addSuiteTab(burpTab)
    }
}