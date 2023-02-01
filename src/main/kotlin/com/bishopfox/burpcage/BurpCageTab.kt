package com.bishopfox.burpcage

import burp.api.montoya.MontoyaApi
import java.awt.Color
import java.awt.GridBagConstraints
import java.awt.GridBagLayout
import java.io.IOException
import java.lang.Exception
import java.net.MalformedURLException
import javax.swing.*
import kotlin.concurrent.thread


class BurpCageTab(private val montoyaApi: MontoyaApi, private val imgList: NicCageImgList) : JPanel() {

    private val errorLabel: JLabel = JLabel("")
    private val jList: JList<NicCageImg> = JList(imgList)

    init {
        this.layout = GridBagLayout()

        /* Add URL text box and button */
        addFirstRow()

        /* Add list of images */
        addSecondRow()

        /* Add delete button */
        addThirdRow()

        /* Add error label */
        addFourthRow()
    }

    /** Save the images in the burp preferences */
    private fun updateState() {
        montoyaApi.persistence().preferences().setString(PREFERENCES_KEY, Utils.serializeToString(imgList))
        displayError("")
    }

    /** Display an error message
     *
     * @param error The error message
     */
    private fun displayError(error: String) {
        if (error == "") return
        errorLabel.text = "Error: $error"
    }

    private fun addFirstRow() {
        val c = GridBagConstraints()

        /* Grid row 0, col 0: label */
        c.fill = GridBagConstraints.HORIZONTAL
        c.gridx = 0
        c.gridy = 0
        this.add(JLabel("Image URL"), c)

        /* Grid row 0, col 1: text */
        val textField = JTextField("", 50)
        c.fill = GridBagConstraints.HORIZONTAL
        c.gridx = 1
        c.gridy = 0
        this.add(textField, c)

        /* Grid row 0, col 2: button */
        val addImgButton = JButton("Add Image")
        addImgButton.addActionListener {/* Disable button while we are in the thread */
            addImgButton.isEnabled = false
            textField.isEnabled = false

            thread(start = true) {
                try {
                    val nicCageImg = NicCageImg(textField.text)
                    imgList.addImage(nicCageImg)

                    /* Automatically save the image */
                    updateState()
                } catch (ex: MalformedURLException) {
                    displayError("Malformed URL. Please validate your URL and try again.")
                    return@thread
                } catch (ex: IOException) {
                    displayError("IO error when downloading the image. Please try again.")
                    return@thread
                } catch (ex: Exception) {
                    displayError("Internal error. Please double check the stack trace for more details.")
                    montoyaApi.logging().logToError(ex.toString())
                    return@thread
                } finally {
                    addImgButton.isEnabled = true
                    textField.isEnabled = true
                }
            }
        }
        c.fill = GridBagConstraints.HORIZONTAL
        c.gridx = 2
        c.gridy = 0
        this.add(addImgButton, c)
    }

    private fun addSecondRow() {
        val c = GridBagConstraints()

        /* Grid row 1, col 0: list of images */
        c.fill = GridBagConstraints.HORIZONTAL
        c.gridx = 0
        c.gridy = 1
        c.gridwidth = 3

        /* Add JList */
        this.add(JScrollPane(jList), c)
    }

    private fun addThirdRow() {
        val c = GridBagConstraints()

        /* Grid row 2, col 0: delete button */
        c.fill = GridBagConstraints.HORIZONTAL
        c.gridx = 0
        c.gridy = 2
        c.gridwidth = 3

        val deleteImgButton = JButton("Delete Selected Image")
        deleteImgButton.addActionListener {
            if (jList.selectedValue == null) {
                displayError("No value selected when attempting to delete image.")
                return@addActionListener
            }

            imgList.removeElementAt(jList.selectedIndex)
            updateState()
        }
        this.add(deleteImgButton, c)
    }

    private fun addFourthRow() {
        val c = GridBagConstraints()

        /* Grid row 3, col 0: error text */
        c.fill = GridBagConstraints.HORIZONTAL
        c.gridx = 0
        c.gridy = 3
        c.gridwidth = 3

        errorLabel.foreground = Color.RED
        this.add(errorLabel, c)
    }
}