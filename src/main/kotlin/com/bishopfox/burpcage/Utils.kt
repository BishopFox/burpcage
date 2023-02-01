package com.bishopfox.burpcage

import java.io.*
import java.util.Base64

class Utils {
    companion object {

        /**
         * Serialize a NicCageImgList to make it easy to interface with the Montoya API for persistence.
         *
         * @param imgList The image list
         * @return The serialized string
         */
        fun serializeToString(imgList: NicCageImgList): String {
            /* Some code inspiration from: https://stackoverflow.com/questions/61046511/how-to-convert-an-object-into-a-byte-array-in-kotlin/63238833#63238833 */
            val byteArrayOutputStream = ByteArrayOutputStream()
            val objectOutputStream: ObjectOutputStream = ObjectOutputStream(byteArrayOutputStream)
            objectOutputStream.writeObject(imgList)
            objectOutputStream.flush()
            val result = byteArrayOutputStream.toByteArray()
            byteArrayOutputStream.close()
            objectOutputStream.close()
            return Base64.getEncoder().encodeToString(result)
        }

        /**
         * Deserialize
         */
        fun deserializeFromString(imgList: String): NicCageImgList {
            val byteArray = Base64.getDecoder().decode(imgList)
            val byteArrayInputStream = ByteArrayInputStream(byteArray)
            val objectInput: ObjectInput
            objectInput = ObjectInputStream(byteArrayInputStream)
            val result = objectInput.readObject() as NicCageImgList
            objectInput.close()
            byteArrayInputStream.close()
            return result
        }
    }
}