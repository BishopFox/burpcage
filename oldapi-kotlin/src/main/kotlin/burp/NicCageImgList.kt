package burp

import javax.swing.DefaultListModel
import kotlin.random.Random

val NicCageImgList = DefaultListModel<NicCageImg>()

fun getRandomImg(): NicCageImg?
{
    /* Return null if no images */
    if (NicCageImgList.isEmpty)
        return null

    return NicCageImgList[Random.nextInt(NicCageImgList.size)]
}