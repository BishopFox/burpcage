package burp

import java.awt.Component
import java.awt.GridBagConstraints
import java.awt.GridBagLayout
import java.io.IOException
import java.net.HttpURLConnection
import java.net.MalformedURLException
import java.net.URL
import javax.swing.*
import kotlin.concurrent.thread


class NicCageBurpTab(private val callbacks: IBurpExtenderCallbacks) : ITab
{

    /**
     * Burp uses this method to obtain the caption that should appear on the
     * custom tab when it is displayed.
     *
     * @return The caption that should appear on the custom tab when it is
     * displayed.
     */
    override fun getTabCaption(): String
    {
        return TAB_NAME
    }

    /**
     * Burp uses this method to obtain the component that should be used as the
     * contents of the custom tab when it is displayed.
     *
     * @return The component that should be used as the contents of the custom
     * tab when it is displayed.
     */
    override fun getUiComponent(): Component
    {
        val panel = JPanel()

        panel.layout = GridBagLayout()
        val c = GridBagConstraints()

        /* Grid row 0, col 0: label */
        c.fill = GridBagConstraints.HORIZONTAL
        c.gridx = 0
        c.gridy = 0
        panel.add(JLabel("Image URL"), c)

        /* Grid row 0, col 1: text */
        val textField = JTextField(NIC_CAGE_EXAMPLE_IMG, 50)
        c.fill = GridBagConstraints.HORIZONTAL
        c.gridx = 1
        c.gridy = 0
        panel.add(textField, c)

        /* Grid row 0, col 2: button */
        val actionButton = JButton("Add Image")
        actionButton.addActionListener {
            /* Disable button while we are in the thread */
            actionButton.isEnabled = false

            /* Parse URL to make sure it's ok */
            val url: URL

            try
            {
                url = URL(textField.text)
            } catch(ex: MalformedURLException)
            {
                callbacks.printError("User attempted to input malformed URL.")
                actionButton.isEnabled = true
                return@addActionListener
            }

            thread(start = true)
            {
                try
                {
                    val httpConnection = url.openConnection() as HttpURLConnection
                    val mimeType = httpConnection.contentType
                    val arr = httpConnection.inputStream.readBytes()

                    NicCageImgList.addElement(NicCageImg(url, mimeType, arr))
                } catch (ex: IOException)
                {
                    callbacks.printError("The URL did not resolve")
                    return@thread
                } finally
                {
                    actionButton.isEnabled = true
                }
            }
        }
        c.fill = GridBagConstraints.HORIZONTAL
        c.gridx = 2
        c.gridy = 0
        panel.add(actionButton, c)

        /* Grid row 1, col 0: list of images */
        c.fill = GridBagConstraints.HORIZONTAL
        c.gridx = 0
        c.gridy = 1
        c.gridwidth = 3

        panel.add(JScrollPane(JList(NicCageImgList)), c)

        return panel
    }
}