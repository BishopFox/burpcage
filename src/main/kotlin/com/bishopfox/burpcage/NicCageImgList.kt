package com.bishopfox.burpcage

import java.io.Serializable
import javax.swing.DefaultListModel
import kotlin.random.Random

class NicCageImgList : DefaultListModel<NicCageImg>(), Serializable {
    /**
     * Add an element to the NicCageImgList
     *
     * @param img The NicCageImg
     */
    fun addImage(img: NicCageImg) {
        super.addElement(img)
    }

    /**
     * Generate a random NicCageImg
     *
     * @throws IllegalStateException If there are no Nic Cage images in the list
     */
    fun getRandomImg(): NicCageImg {/* Throw exception if the list is empty */
        if (super.isEmpty()) throw IllegalStateException("There are no Nic Cage images in the list.")

        /* Randomly select a NicCageImg from the list */
        return super.get(Random.nextInt(super.size()))
    }
}