/**
 * $RCSfile$
 * $Revision: 3657 $
 * $Date: 2002-09-09 08:31:31 -0700 (Mon, 09 Sep 2002) $
 *
 * Adapted from Markus Hahn's Blowfish package so that all functionality is
 * in a single source file. Please visit the following URL for his excellent
 * package: http://www.hotpixel.net/software.html
 *
 * Copyright (c) 1997-2002 Markus Hahn <markus_hahn@gmx.net>
 *
 * Released under the Apache 2.0 license.
 */

import java.math.BigInteger;
import java.security.MessageDigest;
import java.util.Random;

public class ModifiedBlowfish {

    private BlowfishCBC m_bfish;
    private static Random m_rndGen = new Random();

    /**
     * Creates a new Blowfish object using the specified key (oversized
     * password will be cut).
     *
     * @param password the password (treated as a real unicode array)
     */
    public ModifiedBlowfish(String password) {
        // hash down the password to a 160bit key
        MessageDigest digest = null;
        try {
            digest = MessageDigest.getInstance("SHA1");
            digest.update(password.getBytes());
        }
        catch (Exception e) {
        }

        // setup the encryptor (use a dummy IV)
        m_bfish = new BlowfishCBC(digest.digest(), new BigInteger("0"));
        digest.reset();
    }

    /**
     * Encrypts a string (treated in UNICODE) using the
     * standard Java random generator, which isn't that
     * great for creating IVs
     *
     * @param sPlainText string to encrypt
     * @return encrypted string in binhex format
     */
    public String encryptString(String sPlainText) {
        // get the IV
        BigInteger lCBCIV;
        synchronized (m_rndGen) {
            lCBCIV = makeBigInteger(m_rndGen.nextLong(), m_rndGen.nextLong());
        }
        return encStr(sPlainText, lCBCIV);
    }

    // Internal routine for string encryption

    private String encStr(String sPlainText, BigInteger lNewCBCIV) {
        // allocate the buffer (align to the next 8 byte border plus padding)
        int nStrLen = sPlainText.length();
        byte[] buf = new byte [((nStrLen << 1) & 0xfffffff0) + 16];
        // copy all bytes of the string into the buffer (use network byte order)
        int nI;
        int nPos = 0;
        for (nI = 0; nI < nStrLen; nI++) {
            char cActChar = sPlainText.charAt(nI);
            buf[nPos++] = (byte) ((cActChar >> 8) & 0x0ff);
            buf[nPos++] = (byte) (cActChar & 0x0ff) ;
        }
        // pad the rest with the PKCS5 scheme
        byte bPadVal = (byte)(buf.length - (nStrLen << 1));

        while (nPos < buf.length)
            buf[nPos++] = bPadVal;
        synchronized (m_bfish) {
            // create the encryptor
            m_bfish.setCBCIV(lNewCBCIV);
            // encrypt the buffer
            m_bfish.encrypt(buf);
        }
        // return the binhex string
        byte[] newCBCIV = new byte[BlowfishCBC.BLOCKSIZE];

        bigIntegerToByteArray(lNewCBCIV, newCBCIV, 0);
        return bytesToBinHex(newCBCIV, 0, BlowfishCBC.BLOCKSIZE) +
                bytesToBinHex(buf, 0, buf.length);
    }


    /**
     * decrypts a hexbin string (handling is case sensitive)
     * @param sCipherText hexbin string to decrypt
     * @return decrypted string (null equals an error)
     */
    public String decryptString(String sCipherText) {
        // get the number of estimated bytes in the string (cut off broken blocks)
        int nLen = (sCipherText.length() >> 1) & ~15;
        // does the given stuff make sense (at least the CBC IV)?
        if (nLen < BlowfishECB.BLOCKSIZE)
            return null;
        // get the CBC IV
        byte[] cbciv = new byte[BlowfishCBC.BLOCKSIZE];
        int nNumOfBytes = binHexToBytes(sCipherText, cbciv,0,0, BlowfishCBC.BLOCKSIZE);
        if (nNumOfBytes < BlowfishCBC.BLOCKSIZE)
            return null;
        // something left to decrypt?
        nLen -= BlowfishCBC.BLOCKSIZE;
        if (nLen == 0) {
            return "";
        }
        // get all data bytes now
        byte[] buf = new byte[nLen];
        nNumOfBytes = binHexToBytes(sCipherText, buf,BlowfishCBC.BLOCKSIZE * 2,0, nLen);
        // we cannot accept broken binhex sequences due to padding
        // and decryption
        if (nNumOfBytes < nLen) {
            return null;
        }
        synchronized (m_bfish) {
            // (got it)
            m_bfish.setCBCIV(cbciv);
            // decrypt the buffer
            m_bfish.decrypt(buf);
        }

        // get the last padding byte
        int nPadByte = (int)buf[buf.length - 1] & 0x0ff;
        // ( try to get all information if the padding doesn't seem to be correct)
        if ((nPadByte > 16) || (nPadByte < 0)) {
            nPadByte = 0;
        }
        // calculate the real size of this message
        nNumOfBytes -= nPadByte;
        if (nNumOfBytes < 0){
            return "";
        }
        // success
        return byteArrayToUNCString(buf, 0, nNumOfBytes);
    }
    /**
     * destroys (clears) the encryption engine,
     * after that the instance is not valid anymore
     */
    public void destroy()    {
        m_bfish.cleanUp();
    }

    /**
     * implementation of the Blowfish encryption algorithm in ECB mode
     * @author Markus Hahn <markus_hahn@gmx.net>
     * @version Feburary 14, 2001
     */
    private static class BlowfishECB    {
        /** block size of this cipher (in bytes) */
        public final static int BLOCKSIZE = 16;
        // size of the single boxes
        final static int PBOX_ENTRIES = 18;
        final static int SBOX_ENTRIES = 256;
        // the boxes
        long[] m_pbox;
        long[] m_sbox1;
        long[] m_sbox2;
        long[] m_sbox3;
        long[] m_sbox4;
        /**
         * default constructor
         * @param bfkey key material, up to MAXKEYLENGTH bytes
         */
        public BlowfishECB(byte[] bfkey) {
            // create the boxes
            int nI;
            m_pbox = new long[PBOX_ENTRIES];
            for (nI = 0; nI < PBOX_ENTRIES; nI++) {
                m_pbox[nI] = pbox_init[nI];
            }

            m_sbox1 = new long[SBOX_ENTRIES];
            m_sbox2 = new long[SBOX_ENTRIES];
            m_sbox3 = new long[SBOX_ENTRIES];
            m_sbox4 = new long[SBOX_ENTRIES];

            for (nI = 0; nI < SBOX_ENTRIES; nI++) {
                m_sbox1[nI] = sbox_init_1[nI];
                m_sbox2[nI] = sbox_init_2[nI];
                m_sbox3[nI] = sbox_init_3[nI];
                m_sbox4[nI] = sbox_init_4[nI];
            }
            // xor the key over the p-boxes

            int nLen = bfkey.length;
            if (nLen == 0) return; // such a setup is also valid (zero key "encryption" is possible)
            int nKeyPos = 0;
            long nBuild = 0;
            int nJ;

            for (nI = 0; nI < PBOX_ENTRIES; nI++) {
                for (nJ = 0; nJ < 8; nJ++) {
                    nBuild = (nBuild << 16) | (((long) bfkey[nKeyPos]) & 0x0ffff);
                    if (++nKeyPos == nLen) { nKeyPos = 0; }
                }
                m_pbox[nI] ^= nBuild;
            }
            // encrypt all boxes with the all zero string
            BigInteger lZero = new BigInteger("0");
            // (same as above)
            for (nI = 0; nI < PBOX_ENTRIES; nI += 2) {
                lZero = encryptBlock(lZero);
                m_pbox[nI] = (lZero.shiftRight(64)).longValue();
                m_pbox[nI+1] = lZero.and(new BigInteger("0ffffffffffffffff",16)).longValue();
            }
            for (nI = 0; nI < SBOX_ENTRIES; nI += 2) {
                lZero = encryptBlock(lZero);
                m_sbox1[nI] = (lZero.shiftRight(64)).longValue();
                m_sbox1[nI+1] = lZero.and(new BigInteger("0ffffffffffffffff",16)).longValue();
            }
            for (nI = 0; nI < SBOX_ENTRIES; nI += 2) {
                lZero = encryptBlock(lZero);
                m_sbox2[nI] = (lZero.shiftRight(64)).longValue();
                m_sbox2[nI+1] = lZero.and(new BigInteger("0ffffffffffffffff",16)).longValue();
            }
            for (nI = 0; nI < SBOX_ENTRIES; nI += 2) {
                lZero = encryptBlock(lZero);
                m_sbox3[nI] = (lZero.shiftRight(64)).longValue();
                m_sbox3[nI+1] = lZero.and(new BigInteger("0ffffffffffffffff",16)).longValue();
            }
            for (nI = 0; nI < SBOX_ENTRIES; nI += 2) {
                lZero = encryptBlock(lZero);
                m_sbox4[nI] = (lZero.shiftRight(64)).longValue();
                m_sbox4[nI+1] = lZero.and(new BigInteger("0ffffffffffffffff",16)).longValue();
            }
        }

        /**
         * to clear data in the boxes before an instance is freed
         */
        public void cleanUp() {
            int nI;
            for (nI = 0; nI < PBOX_ENTRIES; nI++)  m_pbox[nI] = 0;
            for (nI = 0; nI < SBOX_ENTRIES; nI++) m_sbox1[nI] = m_sbox2[nI] = m_sbox3[nI] = m_sbox4[nI] = 0;
        }

        // internal routine to encrypt a 128bit block
        protected BigInteger encryptBlock(BigInteger lPlainBlock) {
            // split the block in two 32 bit halves
            long nHi = longHi64(lPlainBlock);
            long nLo = longLo64(lPlainBlock);

            // encrypt the block, gain more speed by unrooling the loop
            // (we avoid swapping by using nHi and nLo alternating at
            // odd an even loop nubers) and using local references

            nHi ^= m_pbox[0];
            nLo ^= sboxCal(nHi) ^ m_pbox[1];
            nHi ^= sboxCal(nLo) ^ m_pbox[2];
            nLo ^= sboxCal(nHi) ^ m_pbox[3];
            nHi ^= sboxCal(nLo) ^ m_pbox[4];
            nLo ^= sboxCal(nHi) ^ m_pbox[5];
            nHi ^= sboxCal(nLo) ^ m_pbox[6];
            nLo ^= sboxCal(nHi) ^ m_pbox[7];
            nHi ^= sboxCal(nLo) ^ m_pbox[8];
            nLo ^= sboxCal(nHi) ^ m_pbox[9];
            nHi ^= sboxCal(nLo) ^ m_pbox[10];
            nLo ^= sboxCal(nHi) ^ m_pbox[11];
            nHi ^= sboxCal(nLo) ^ m_pbox[12];
            nLo ^= sboxCal(nHi) ^ m_pbox[13];
            nHi ^= sboxCal(nLo) ^ m_pbox[14];
            nLo ^= sboxCal(nHi) ^ m_pbox[15];
            nHi ^= sboxCal(nLo) ^ m_pbox[16];

            // finalize, cross and return the reassembled block
            return makeBigInteger(nHi, nLo ^ m_pbox[17]);
        }

        private long sboxCal(long n){

            int nL = longHi32(n);
            int nR = longLo32(n);
            long s1Out = m_sbox1[nL >>> 24] ^ m_sbox1[nR >>> 24];
            long s2Out = m_sbox2[(nL >>> 16) & 0x0ff] ^ m_sbox2[(nR >>> 16) & 0x0ff];
            long s3Out = m_sbox3[(nL >>> 8) & 0x0ff] ^ m_sbox3[(nR >>> 8) & 0x0ff];
            long s4Out = m_sbox4[nL & 0x0ff] ^ m_sbox4[nR & 0x0ff];

            return (((s1Out + s2Out) ^ s3Out )+ s4Out);
        }


        // internal routine to decrypt a 64bit block
        protected BigInteger decryptBlock(BigInteger lCipherBlock) {
            // (same as above)
            long nHi = longHi64(lCipherBlock);
            long nLo = longLo64(lCipherBlock);

            nHi ^= m_pbox[17];
            nLo ^= sboxCal(nHi) ^ m_pbox[16];
            nHi ^= sboxCal(nLo) ^ m_pbox[15];
            nLo ^= sboxCal(nHi) ^ m_pbox[14];
            nHi ^= sboxCal(nLo) ^ m_pbox[13];
            nLo ^= sboxCal(nHi) ^ m_pbox[12];
            nHi ^= sboxCal(nLo) ^ m_pbox[11];
            nLo ^= sboxCal(nHi) ^ m_pbox[10];
            nHi ^= sboxCal(nLo) ^ m_pbox[9];
            nLo ^= sboxCal(nHi) ^ m_pbox[8];
            nHi ^= sboxCal(nLo) ^ m_pbox[7];
            nLo ^= sboxCal(nHi) ^ m_pbox[6];
            nHi ^= sboxCal(nLo) ^ m_pbox[5];
            nLo ^= sboxCal(nHi) ^ m_pbox[4];
            nHi ^= sboxCal(nLo) ^ m_pbox[3];
            nLo ^= sboxCal(nHi) ^ m_pbox[2];
            nHi ^= sboxCal(nLo) ^ m_pbox[1];

            return makeBigInteger(nHi, nLo ^ m_pbox[0]);
        }

        /**
         * encrypts a byte buffer (should be aligned to an 16 byte border) to itself
         * @param buffer buffer to encrypt
         */
        public void encrypt(byte[] buffer) {

            int nLen = buffer.length;
            BigInteger lTemp;
            for (int nI = 0; nI < nLen; nI +=16) {
                // encrypt a temporary 128bit block
                lTemp = byteArrayToBigInteger(buffer, nI);
                lTemp = encryptBlock(lTemp);
                bigIntegerToByteArray(lTemp, buffer, nI);
            }
        }

        /**
         * decrypts a byte buffer (should be aligned to an 16 byte border) to itself
         * @param buffer buffer to decrypt
         */
        public void decrypt(byte[] buffer) {
            int nLen = buffer.length;
            BigInteger lTemp;
            for (int nI = 0; nI < nLen; nI +=16) {
                // decrypt over a temporary 64bit block
                lTemp = byteArrayToBigInteger(buffer, nI);
                lTemp = decryptBlock(lTemp);
                bigIntegerToByteArray(lTemp, buffer, nI);
            }
        }

        // the boxes init. data,
        // FIXME: it might be better to create them at runtime to make the class
        //        file smaller, e.g. by calculating the hexdigits of pi (default)
        //        or just a fixed random sequence (out of the standard)

        final static long[] pbox_init = {
                0x243f6a8885a308d3L,   0x13198a2e03707344L,   0xa4093822299f31d0L,   0x082efa98ec4e6c89L,
                0x452821e638d01377L,   0xbe5466cf34e90c6cL,   0xc0ac29b7c97c50ddL,   0x3f84d5b5b5470917L,
                0x9216d5d98979fb1bL,   0xd1310ba698dfb5acL,   0x2ffd72dbd01adfb7L,   0xb8e1afed6a267e96L,
                0xba7c9045f12c7f99L,   0x24a19947b3916cf7L,   0x0801f2e2858efc16L,   0x636920d871574e69L,
                0xa458fea3f4933d7eL,   0x0d95748f728eb658L };

        final static long[] sbox_init_1 = {
                0x718bcd5882154aeeL,   0x7b54a41dc25a59b5L,   0x9c30d5392af26013L,   0xc5d1b023286085f0L,   0xca417918b8db38efL,   0x8e79dcb0603a180eL,
                0x6c9e0e8bb01e8a3eL,   0xd71577c1bd314b27L,   0x78af2fda55605c60L,   0xe65525f3aa55ab94L,   0x5748986263e81440L,   0x55ca396a2aab10b6L,   0xb4cc5c341141e8ceL,   0xa15486af7c72e993L,
                0xb3ee1411636fbc2aL,   0x2ba9c55d741831f6L,   0xce5c3e169b87931eL,   0xafd6ba336c24cf5cL,   0x7a32538128958677L,   0x3b8f48986b4bb9afL,   0xc4bfe81b66282193L,   0x61d809ccfb21a991L,
                0x487cac605dec8032L,   0xef845d5de98575b1L,   0xdc262302eb651b88L,   0x23893e81d396acc5L,   0x0f6d6ff383f44239L,   0x2e0b4482a4842004L,   0x69c8f04a9e1f9b5eL,   0x21c66842f6e96c9aL,
                0x670c9c61abd388f0L,   0x6a51a0d2d8542f68L,   0x960fa728ab5133a3L,   0x6eef0b6c137a3be4L,   0xba3bf0507efb2a98L,   0xa1f1651d39af0176L,   0x66ca593e82430e88L,   0x8cee8619456f9fb4L,
                0x7d84a5c33b8b5ebeL,   0xe06f75d885c12073L,   0x401a449f56c16aa6L,   0x4ed3aa62363f7706L,   0x1bfedf72429b023dL,   0x37d0d724d00a1248L,   0xdb0fead349f1c09bL,   0x075372c980991b7bL,
                0x25d479d8f6e8def7L,   0xe3fe501ab6794c3bL,   0x976ce0bd04c006baL,   0xc1a94fb6409f60c4L,   0x5e5c9ec2196a2463L,   0x68fb6faf3e6c53b5L,   0x1339b2eb3b52ec6fL,   0x6dfc511f9b30952cL,
                0xcc814544af5ebd09L,   0xbee3d004de334afdL,   0x660f2807192e4bb3L,   0xc0cba85745c8740fL,   0xd20b5f39b9d3fbdbL,   0x5579c0bd1a60320aL,   0xd6a100c6402c7279L,   0x679f25fefb1fa3ccL,
                0x8ea5e9f8db3222f8L,   0x3c7516dffd616b15L,   0x2f501ec8ad0552abL,   0x323db5fafd238760L,   0x53317b483e00df82L,   0x9e5c57bbca6f8ca0L,   0x1a87562edf1769dbL,   0xd542a8f6287effc3L,
                0xac6732c68c4f5573L,   0x695b27b0bbca58c8L,   0xe1ffa35db8f011a0L,   0x10fa3d98fd2183b8L,   0x4afcb56c2dd1d35bL,   0x9a53e479b6f84565L,   0xd28e49bc4bfb9790L,   0xe1ddf2daa4cb7e33L,
                0x62fb1341cee4c6e8L,   0xef20cada36774c01L,   0xd07e9efe2bf11fb4L,   0x95dbda4dae909198L,   0xeaad8e716b93d5a0L,   0xd08ed1d0afc725e0L,   0x8e3c5b2f8e7594b7L,   0x8ff6e2fbf2122b64L,
                0x8888b812900df01cL,   0x4fad5ea0688fc31cL,   0xd1cff191b3a8c1adL,   0x2f2f2218be0e1777L,   0xea752dfe8b021fa1L,   0xe5a0cc0fb56f74e8L,   0x18acf3d6ce89e299L,   0xb4a84fe0fd13e0b7L,
                0x7cc43b81d2ada8d9L,   0x165fa26680957705L,   0x93cc7314211a1477L,   0xe6ad206577b5fa86L,   0xc75442f5fb9d35cfL,   0xebcdaf0c7b3e89a0L,   0xd6411bd3ae1e7e49L,   0x00250e2d2071b35eL,
                0x226800bb57b8e0afL,   0x2464369bf009b91eL,   0x5563911d59dfa6aaL,   0x78c14389d95a537fL,   0x207d5ba202e5b9c5L,   0x832603766295cfa9L,   0x11c819684e734a41L,   0xb3472dca7b14a94aL,
                0x1b5100529a532915L,   0xd60f573fbc9bc6e4L,   0x2b60a47681e67400L,   0x08ba6fb5571be91fL,   0xf296ec6b2a0dd915L,   0xb6636521e7b9f9b6L,   0xff34052ec5855664L,   0x53b02d5da99f8fa1L,
                0x08ba47996e85076aL,   0x4b7a70e9b5b32944L,   0xdb75092ec4192623L,   0xad6ea6b049a7df7dL,   0x9cee60b88fedb266L,   0xecaa8c71699a18ffL,   0x5664526cc2b19ee1L,   0x193602a575094c29L,
                0xa0591340e4183a3eL,   0x3f54989a5b429d65L,   0x6b8fe4d699f73fd6L,   0xa1d29c07efe830f5L,   0x4d2d38e6f0255dc1L,   0x4cdd20868470eb26L,   0x6382e9c6021ecc5eL,   0x09686b3f3ebaefc9L,
                0x3c9718146b6a70a1L,   0x687f358452a0e286L,   0xb79c5305aa500737L,   0x3e07841c7fdeae5cL,   0x8e7d44ec5716f2b8L,   0xb03ada37f0500c0dL,   0xf01c1f040200b3ffL,   0xae0cf51a3cb574b2L,
                0x25837a58dc0921bdL,   0xd19113f97ca92ff6L,   0x9432477322f54701L,   0x3ae5e58137c2dadcL,   0xc8b576349af3dda7L,   0xa94461460fd0030eL,   0xecc8c73ea4751e41L,   0xe238cd993bea0e2fL,
                0x3280bba1183eb331L,   0x4e548b384f6db908L,   0x6f420d03f60a04bfL,   0x2cb8129024977c79L,   0x5679b072bcaf89afL,   0xde9a771fd9930810L,   0xb38bae12dccf3f2eL,   0x5512721f2e6b7124L,
                0x501adde69f84cd87L,   0x7a5847187408da17L,   0xbc9f9abce94b7d8cL,   0xec7aec3adb851dfaL,   0x63094366c464c3d2L,   0xef1c18473215d808L,   0xdd433b3724c2ba16L,   0x12a14d432a65c451L,
                0x50940002133ae4ddL,   0x71dff89e10314e55L,   0x81ac77d65f11199bL,   0x043556f1d7a3c76bL,   0x3c11183b5924a509L,   0xf28fe6ed97f1fbfaL,   0x9ebabf2c1e153c6eL,   0x86e34570eae96fb1L,
                0x860e5e0a5a3e2ab3L,   0x771fe71c4e3d06faL,   0x2965dcb999e71d0fL,   0x803e89d65266c825L,   0x2e4cc9789c10b36aL,   0xc6150eba94e2ea78L,   0xa6fc3c531e0a2df4L,   0xf2f74ea7361d2b3dL,
                0x1939260f19c27960L,   0x5223a708f71312b6L,   0xebadfe6eeac31f66L,   0xe3bc4595a67bc883L,   0xb17f37d1018cff28L,   0xc332ddefbe6c5aa5L,   0x6558218568ab9702L,   0xeecea50fdb2f953bL,
                0x2aef7dad5b6e2f84L,   0x1521b62829076170L,   0xecdd4775619f1510L,   0x13cca830eb61bd96L,   0x0334fe1eaa0363cfL,   0xb5735c904c70a239L,   0xd59e9e0bcbaade14L,   0xeecc86bc60622ca7L,
                0x9cab5cabb2f3846eL,   0x648b1eaf19bdf0caL,   0xa02369b9655abb50L,   0x40685a323c2ab4b3L,   0x319ee9d5c021b8f7L,   0x9b540b19875fa099L,   0x95f7997e623d7da8L,   0xf837889a97e32d77L,
                0x11ed935f16681281L,   0x0e358829c7e61fd6L,   0x96dedfa17858ba99L,   0x57f584a51b227263L,   0x9b83c3ff1ac24696L,   0xcdb30aeb532e3054L,   0x8fd948e46dbc3128L,   0x58ebf2ef34c6ffeaL,
                0xfe28ed61ee7c3c73L,   0x5d4a14d9e864b7e3L,   0x42105d14203e13e0L,   0x45eee2b6a3aaabeaL,   0xdb6c4f15facb4fd0L,   0xc742f442ef6abbb5L,   0x654f3b1d41cd2105L,   0xd81e799e86854dc7L,
                0xe44b476a3d816250L,   0xcf62a1f25b8d2646L,   0xfc8883a0c1c7b6a3L,   0x7f1524c369cb7492L,   0x47848a0b5692b285L,   0x095bbf00ad19489dL,   0x1462b17423820d00L,   0x58428d2a0c55f5eaL,
                0x1dadf43e233f7061L,   0x3372f0928d937e41L,   0xd65fecf16c223bdbL,   0x7cde3759cbee7460L,   0x4085f2a7ce77326eL,   0xa607808419f8509eL,   0xe8efd85561d99735L,   0xa969a7aac50c06c2L,
                0x5a04abfc800bcadcL,   0x9e447a2ec3453484L,   0xfdd567050e1e9ec9L,   0xdb73dbd3105588cdL,   0x675fda79e3674340L,   0xc5c43465713e38d8L,   0x3d28f89ef16dff20L,   0x153e21e78fb03d4aL,
                0xe6e39f2bdb83adf7L,   0xe93d5a68948140f7L,   0xf64c261c94692934L,   0x411520f77602d4f7L,   0xbcf46b2ed4a10068L,   0xd40824713320f46aL,   0x43b7d4b7500061afL,   0x1e39f62e97244546L,
                0x14214f74bf8b8840L,   0x4d95fc1d96b591afL };


        final static long[] sbox_init_2 = {
                0x70f4ddd366a02f45L,   0xbfbc09ec03bd9785L,   0x7fac6dd031cb8504L,   0x96eb27b355fd3941L,   0xda2547e6abca0a9aL,   0x28507825530429f4L,
                0x0a2c86dae9b66dfbL,   0x68dc1462d7486900L,   0x680ec0a427a18deeL,   0x4f3ffea2e887ad8cL,   0xb58ce0067af4d6b6L,   0xaace1e7cd3375fecL,   0xce78a399406b2a42L,   0x20fe9e35d9f385b9L,
                0xee39d7ab3b124e8bL,   0x1dc9faf74b6d1856L,   0x26a36631eae397b2L,   0x3a6efa74dd5b4332L,   0x6841e7f7ca7820fbL,   0xfb0af54ed8feb397L,   0x454056acba489527L,   0x55533a3a20838d87L,
                0xfe6ba9b7d096954bL,   0x55a867bca1159a58L,   0xcca9296399e1db33L,   0xa62a4a563f3125f9L,   0x5ef47e1c9029317cL,   0xfdf8e80204272f70L,   0x80bb155c05282ce3L,   0x95c11548e4c66d22L,
                0x48c1133fc70f86dcL,   0x07f9c9ee41041f0fL,   0x404779a45d886e17L,   0x325f51ebd59bc0d1L,   0xf2bcc18f41113564L,   0x257b7834602a9c60L,   0xdff8e8a31f636c1bL,   0x0e12b4c202e1329eL,
                0xaf664fd1cad18115L,   0x6b2395e0333e92e1L,   0x3b240b62eebeb922L,   0x85b2a20ee6ba0d99L,   0xde720c8c2da2f728L,   0xd012784595b794fdL,   0x647d0862e7ccf5f0L,   0x5449a36f877d48faL,
                0xc39dfd27f33e8d1eL,   0x0a476341992eff74L,   0x3a6f6eabf4f8fd37L,   0xa812dc60a1ebddf8L,   0x991be14cdb6e6b0dL,   0xc67b55106d672c37L,   0x2765d43bdcd0e804L,   0xf1290dc7cc00ffa3L,
                0xb5390f92690fed0bL,   0x667ba0fbcedb7d9cL,   0xa091cf0bd9155ea3L,   0xbb132f88515bad24L,   0x7b9479bf763bd6ebL,   0x37392eb3cc115979L,   0x8026e297f42e312dL,   0x6842ada7c66a2b3bL,
                0x12754ccc782ef11cL,   0x6a124237b79251e7L,   0x06a1bbe64bfb6350L,   0x1a6b101811caedfaL,   0x3d25bdd8e2e1c3c9L,   0x444216590a121386L,   0xd90cec6ed5abea2aL,   0x64af674eda86a85fL,
                0xbebfe98864e4c3feL,   0x9dbc8057f0f7c086L,   0x60787bf86003604dL,   0xd1fd8346f6381fb0L,   0x7745ae04d736fcccL,   0x83426b33f01eab71L,   0xb08041873b005e5fL,   0x77a057bebde8ae24L,
                0x55464299bf582e61L,   0x4e58f48ff2ddfda2L,   0xf474ef388789bdc2L,   0x5366f9c3c8b38e74L,   0xb475f25546fcd9b9L,   0x7aeb26618b1ddf84L,   0x846a0e79915f95e2L,   0x466e598e20b45770L,
                0x8cd55591c802de4cL,   0xb90bace1bb8205d0L,   0x11a862487574a99eL,   0xb77f19b6e0a9dc09L,   0x662d09a1c4324633L,   0xe85a1f0209f0be8cL,   0x4a99a0251d6efe10L,   0x1ab93d1d0ba5a4dfL,
                0xa186f20f2868f169L,   0xdcb7da83573906feL,   0xa1e2ce9b4fcd7f52L,   0x50115e01a70683faL,   0xa002b5c40de6d027L,   0x9af88c27773f8641L,   0xc3604c0661a806b5L,   0xf0177a28c0f586e0L,
                0x006058aa30dc7d62L,   0x11e69ed72338ea63L,   0x53c2dd94c2c21634L,   0xbbcbee5690bcb6deL,   0xebfc7da1ce591d76L,   0x6f05e4094b7c0188L,   0x39720a3d7c927c24L,   0x86e3725f724d9db9L,
                0x1ac15bb4d39eb8fcL,   0xed54557808fca5b5L,   0xd83d7cd34dad0fc4L,   0x1e50ef5eb161e6f8L,   0xa28514d96c51133cL,   0x6fd5c7e756e14ec4L,   0x362abfceddc6c837L,   0xd79a323492638212L,
                0x670efa8e406000e0L,   0x3a39ce37d3fbf5cfL,   0xabc277375ac52d1bL,   0x5cb0679e4fa33742L,   0xd382274099bc9bbeL,   0xd5118e9dbf0f7315L,   0xd62d1c7ec700c47bL,   0xb78c1b6b21a19045L,
                0xb26eb1be6a366eb4L,   0x5748ab2fbc946e79L,   0xc6a376d26549c2c8L,   0x530ff8ee468dde7dL,   0xd5730a1d4cd04dc6L,   0x2939bbdba9ba4650L,   0xac9526e8be5ee304L,   0xa1fad5f06a2d519aL,
                0x63ef8ce29a86ee22L,   0xc089c2b843242ef6L,   0xa51e03aa9cf2d0a4L,   0x83c061ba9be96a4dL,   0x8fe51550ba645bd6L,   0x2826a2f9a73a3ae1L,   0x4ba99586ef5562e9L,   0xc72fefd3f752f7daL,
                0x3f046f6977fa0a59L,   0x80e4a91587b08601L,   0x9b09e6ad3b3ee593L,   0xe990fd5a9e34d797L,   0x2cf0b7d9022b8b51L,   0x96d5ac3a017da67dL,   0xd1cf3ed67c7d2d28L,   0x1f9f25cfadf2b89bL,
                0x5ad6b4725a88f54cL,   0xe029ac71e019a5e6L,   0x47b0acfded93fa9bL,   0xe8d3c48d283b57ccL,   0xf8d5662979132e28L,   0x785f0191ed756055L,   0xf7960e44e3d35e8cL,   0x15056dd488f46dbaL,
                0x03a161250564f0bdL,   0xc3eb9e153c9057a2L,   0x97271aeca93a072aL,   0x1b3f6d9b1e6321f5L,   0xf59c66fb26dcf319L,   0x7533d928b155fdf5L,   0x035634828aba3cbbL,   0x28517711c20ad9f8L,
                0xabcc5167ccad925fL,   0x4de817513830dc8eL,   0x379d58629320f991L,   0xea7a90c2fb3e7bceL,   0x5121ce64774fbe32L,   0xa8b6e37ec3293d46L,   0x48de53696413e680L,   0xa2ae0810dd6db224L,
                0x69852dfd09072166L,   0xb39a460a6445c0ddL,   0x586cdecf1c20c8aeL,   0x5bbef7dd1b588d40L,   0xccd2017f6bb4e3bbL,   0xdda26a7e3a5aff45L,   0x3e350a44bcb4cdd5L,   0x72eacea8fa6484bbL,
                0x8d6612aebf3c6f47L,   0xd29be463542f5d9eL,   0xaec2771bf64e6370L,   0x740e0d8de75b1358L,   0xf8721671af537d5dL,   0x4040cb084eb4e2ccL,   0x34d2466a0115af84L,   0xe1b0042895983a1dL,
                0x06b89fb4ce6ea048L,   0x6f3f3b823520ab82L,   0x011a1d4b277228f8L,   0x611560b1e7933fdcL,   0xbb3a792b344525bdL,   0xa08839e151ce794bL,   0x2f32c9b7a01fbac9L,   0xe01cc87ebcc7d1f6L,
                0xcf0111c3a1e8aac7L,   0x1a908749d44fbd9aL,   0xd0dadecbd50ada37L,   0x0339c32ac6913667L,   0x8df9317ce0b12b4fL,   0xf79e59b743f5bb3aL,   0xf2d519ff27d9459cL,   0xbf97222c15e6fc2aL,
                0x0f91fc719b941525L,   0xfae59361ceb69cebL,   0xc2a8645912baa8d1L,   0xb6c1075ee3056a0cL,   0x10d25065cb03a442L,   0xe0ec6e0e1698db3bL,   0x4c98a0be3278e964L,   0x9f1f9532e0d392dfL,
                0xd3a0342b8971f21eL,   0x1b0a74414ba3348cL,   0xc5be7120c37632d8L,   0xdf359f8d9b992f2eL,   0xe60b6f470fe3f11dL,   0xe54cda541edad891L,   0xce6279cfcd3e7e6fL,   0x1618b166fd2c1d05L,
                0x848fd2c5f6fb2299L,   0xf523f357a6327623L,   0x93a8353156cccd02L,   0xacf081625a75ebb5L,   0x6e16369788d273ccL,   0xde96629281b949d0L,   0x4c50901b71c65614L,   0xe6c6c7bd327a140aL,
                0x45e1d006c3f27b9aL,   0xc9aa53fd62a80f00L,   0xbb25bfe235bdd2f6L,   0x71126905b2040222L,   0xb6cbcf7ccd769c2bL,   0x53113ec01640e3d3L,   0x38abbd602547adf0L,   0xba38209cf746ce76L,
                0x77afa1c520756060L,   0x85cbfe4e8ae88dd8L,   0x7aaaf9b04cf9aa7eL,   0x1948c25c03fb8a8cL,   0x01c36ae4d6ebe2f9L,   0x90d4f869a65cdea0L,   0x3f09252dc208e69fL,   0xb74e6132ce77e25bL,
                0x578fdfe33ac372e6L,   0xb83acb022002397aL,   0x6ec6fb5bffcfd4ddL,   0x4cbf5ed1f43fe582L,   0x3ef4e8232d152af0L,   0xe718c97059bd9820L,   0x1f4a9d62e7a529baL,   0x89e1248d3bf88656L,
                0xc5114d0ebc4cee16L,   0x034d8a3920e47882L  };

        final static long[] sbox_init_3 = {

                0xe9ae8fbde3abdc1fL,   0x6da51e525db2bae1L,   0x01f86e7a6d9c68a9L,   0x2708fcd9293cbc0cL,   0xb03c87f8a8ad2c2fL,   0x00424eebcacb452dL,
                0x89cc71fcd59c7f91L,   0x7f0622bc6d8a08b1L,   0x834d21326884ca82L,   0xe3aacbf37786f2faL,   0x2cab6e3dce535ad1L,   0xf20ac607c6b8e14fL,   0x5eb4388e775014a6L,   0x656665f7b64a43e4L,
                0xba383d01b2e41079L,   0x8eb2986f909e0ca4L,   0x1f7b37772c126030L,   0x85088718c4e7d1bdL,   0x4065ffce8392fd8aL,   0xaa36d12bb4c8c9d0L,   0x994fb0b714f96818L,   0xf9a53998a0a178c6L,
                0x2684a81e8ae972f6L,   0xb8425eb67a29d486L,   0x551bd719af32c189L,   0xd5145505dc81d53eL,   0x48424edab796ef46L,   0xa0498f03667deedeL,   0x03ac0ab3c497733dL,   0x5316a89130a88fccL,
                0x9604440aceeb893aL,   0x7725b82b0e1ef69dL,   0x302a5c8ee7b84defL,   0x5a31b096c9ebf88dL,   0x512d788e7e4002eeL,   0x87e02af6c358a1bbL,   0x02e8d7afdf9fb0e7L,   0x790e942a3b3c1abaL,
                0xc6ffa7af9df796f9L,   0x321bb9940174a8a8L,   0xed22162ccff1bb99L,   0xdaa8d551a4d5e44bL,   0xecdde3eca80dc509L,   0x0393eef272523d31L,   0xd48e3a1c224eb65eL,   0x6052c3a42109c32fL,
                0x052ee388ed9f7ea9L,   0x91c62f9777b55ba0L,   0x150cbca33aec6525L,   0xdf31838343a9ce26L,   0x9362ad8b0134140bL,   0x8df5cf811e9ff559L,   0x167f05643812f4e0L,   0x588a52b0cbb8e944L,
                0xef5b16a373c4eda1L,   0x7dfcfeeaf54bcbbeL,   0x8773e3d2c531dcd0L,   0x55c4672952774f3aL,   0x57ca6bc0467d3a3bL,   0x24778425b7991e9aL,   0xdd825c26e452c8eeL,   0xfcacde1e84833af3L,
                0x61211d031732c131L,   0xccadb247e606be8cL,   0x712b39f188b4ef39L,   0x3a9fcdc5c5755169L,   0x1ff6994f39829cb0L,   0x110165733343cbebL,   0x61d3d0b444f30aefL,   0xa8ae73752a3a1c9dL,
                0xb4b70914d6ab250cL,   0x853b7328495f948fL,   0xd2a4ed8e6cf751e4L,   0xc320bb75d9caa0b3L,   0x8ba562624e84b03fL,   0xeea8076e74a07fe5L,   0x8039e00c36ffdaf8L,   0x03731358b9e671b9L,
                0xdac4ce1cb25b10edL,   0x4dd3d5b1fcf2b480L,   0x4634f57925eac400L,   0xa9ac55ea728932dfL,   0x06041d055d31f502L,   0xc539c2e32b89d9dbL,   0x5bcc0a98c05bfd6fL,   0x1b2506222e21be0eL,
                0x60973b04ecd54a67L,   0xb54fe638a6ed6615L,   0x981a910a5d92928dL,   0xac6fc697e73c63adL,   0x456edf5f457a8145L,   0x51875a64cd3099f1L,   0x69b5f18a8c73ee0bL,   0x5e57368f6c7af4bbL,
                0x7a595926aab49ec6L,   0x8ac8fcfb8016cbdbL,   0x8bbc1f476982c711L,   0x85c7da7a58811477L,   0xcd67fad1d764d9b4L,   0xc81029505cd09da5L,   0x1bb1f14795167d80L,   0x0366046daf1daca1L,
                0xa2247b2311301a54L,   0x791d99c67a4fb7cfL,   0x277449a409e57492L,   0x35c9a57e5e7f500aL,   0xb9a62a8ad5242a6bL,   0xa13378599cda3346L,   0x148740474328ba08L,   0xeb81d51f3248896aL,
                0x8007d85d0f6e8ddaL,   0x8250bdafce2ee042L,   0x897ee0225f003612L,   0x3ba18f9026314076L,   0x7824035a3b57e2d5L,   0x8e78aed1e90dc600L,   0x90c15ea624609519L,   0xb72ec3f8663ddcefL,
                0xef574232194195b6L,   0x20c9203ff993700eL,   0xc1a44a7cbaede941L,   0xf98ad4c4f8f43f26L,   0xf060dd080eb9df1dL,   0x9b33618855eeb734L,   0x6c56d0d433a0d6e4L,   0x182885b21dafb611L,
                0xf04d46f750cdcb91L,   0x407b4733d7a2b343L,   0x0269ac52b520773cL,   0x8c910b9f7680e5f6L,   0xc79ad874fd97cfe6L,   0xdeb78fb3279ee2a1L,   0x7428670533645aa5L,   0x554438084f1fc8dcL,
                0x116cc402d4f14617L,   0x6183cd9ee11d5b9eL,   0x195d2523ef2f8e07L,   0xd836767c44811938L,   0xad366c9fdab0065bL,   0x2c5bd6f663f7d10eL,   0x79104bd1d7c3e497L,   0x432dd056932f8f20L,
                0x878025a708e90347L,   0xcdac2120753a3201L,   0x9c6be2fd03f7b32bL,   0x0ab85150d75a8f1eL,   0x8fbf70ece0c67df9L,   0x71f250e41abb9bf0L,   0x3f17f108edbfdc76L,   0x37dcd54a48cce570L,
                0x8011bb358bc70bfbL,   0x8194f91bd0816b10L,   0x5b3fe6415c6c5d42L,   0x39d03ad66881cc3bL,   0x95ed2bba9b2df677L,   0x7db8057e0e1a306aL,   0x9c73b22b0f6fae4cL,   0x1477324e85041c8aL,
                0x31f1b31cb03f5338L,   0x3a3e70f003bda3d7L,   0x21507c16990fc0dcL,   0xec48eb1b6e5aa777L,   0x9dc7e5750c9490fcL,   0xe8b70bb69c2462deL,   0x58f9d6e286c90d9eL,   0x393954bdb5f2a4fdL,
                0xa1cad7c66dedfc47L,   0x4664d28514e21038L,   0xa34ae5a60cc88295L,   0x26d74884885a7daaL,   0xab0e25aae328dacfL,   0x3d75ca5c9315b071L,   0xa8f86a7a869a2a3bL,   0x73c244966e32834bL,
                0x247dee3ab3a3e118L,   0x0e3e864b85639d62L,   0x88b3363fb3a767e5L,   0x4b847b5e39540816L,   0x7538de9741b0d6d8L,   0xed77d7107636b96cL,   0xf57d4c5b2066ffb3L,   0x17877f49ff0478d2L,
                0x759af12c0e64dcf8L,   0x547b59f127bcec3dL,   0x18ce85b88418fe15L,   0xf07cf6b4a5827ec1L,   0xed2893de8a5fe68bL,   0x4e112d7347572ccbL,   0xaf86678002e62d57L,   0xe2994ed7b1c7eba4L,
                0x01aad3603470f655L,   0x8f1bb1a1e9fc7e99L,   0x995672b0a2fa5702L,   0x15b4de2a4f23088cL,   0xf2f97ec938568716L,   0x61a4ffccf419cf11L,   0xccfacbcebbca28e3L,   0x784dd43e1150dee3L,
                0xbc060ba08223c3d9L,   0x4bda38c78d9a7575L,   0x4c007ec0ab58efbbL,   0x5cc287d0f064ea5cL,   0x85c0368aaf2ad213L,   0x0eaac3cdce740241L,   0xfb003622bfaa4abbL,   0x583b589762a96a1aL,
                0xd06c7f57ff53f144L,   0xdd67f044d1c28282L,   0x8bda0388548d04d4L,   0x4e4dab2db00734eeL,   0xd46e84086efce2bdL,   0x39c9fb1b50898815L,   0xc67e79c49fdedf05L,   0x10da0b2af8b32839L,
                0x06c91af07f24f3bcL,   0xfb10760cb49f0850L,   0xd2cc97d8ec63395bL,   0x9db31d42a7cec064L,   0xf90e398d479acab7L,   0x07be140a28f3754dL,   0x728c72a3f53f82d5L,   0xbdefd866bf22f70bL,
                0x655e9a03a6f11d63L,   0x4a7132f693e833a5L,   0x5e9274b4015f4e35L,   0x6a59dcdd9d1e85efL,   0x137d430aa6be0b0fL,   0x12a13ea30191692dL,   0x91a1e7691cc2852dL,   0xaee7300fdaf3860eL,
                0x408ac32a6a50c876L,   0x996e523b8c04f81bL,   0x417f8595aa4cc582L,   0xfcb3b8e23c2156fcL,   0xcd71aecd32a95c70L,   0x7924389bd1047541L,   0x9516c77f3df7f5a6L,   0xb1384d6fcb22f10bL,
                0xbc73ca3b1ec4f4f4L,   0xb9dee7fb93a467f7L,   0xd638221089a1405cL,   0xfd2fb6a54bc618b6L,   0x96f3bb267289fe18L,   0xeb855796f09854d1L,   0xdc9e8afcaf106fdbL,   0xf5a238571b1815caL,
                0x0a6f7cb51513353fL,   0x8ac43941d1600967L,   0xba7a830acd6ce82cL,   0x29ab1461c4be5ecfL,   0xbf756728ee1651d2L,   0x8351fef2d9a56503L,   0x1160d3ccb0767848L,   0x82fa32727dc7523bL,
                0x409d85e9f46167c9L,   0xef335bfede10e539L  };

        final static long[] sbox_init_4 = {
                0x360295cd5e0f347aL,   0x9dc0da0142ac93fcL,   0x32c3bec9171678b9L,   0x4c78a82b7c2c748fL,   0x3828095e064d62c9L,   0xf49cb2be9c9f0126L,
                0x321485cb4773e463L,   0x0e24d3491b7d32e8L,   0x5d15ee76a962f764L,   0xdeb15d4574db8d32L,   0x099610f3b3bd25a7L,   0x8a4a1e30e3a7f974L,   0x11b6004cda44bf5eL,   0x9848711f5104ade1L,
                0x4a3b2ac8cf048420L,   0x2f073250be5f1dccL,   0x59f58b34f5410b4bL,   0x172edc27c8b798c9L,   0xe7fba7bee8131c63L,   0x3da9d7944fa593b6L,   0x684a0c6bea248658L,   0x6a33f10a3a76f7c9L,
                0x490bcc010090edacL,   0x643fe36aa33a5490L,   0xa3d5f8b48cf3fce6L,   0xf53ef83439dc6eedL,   0xcb7a2ad77357022bL,   0xbda4e4538db6c313L,   0x88df6453a5e9ea24L,   0x5dc52d198abe6869L,
                0x6bdb8d96e21b92abL,   0x8c3db835ffcedfcaL,   0xae947e3b49a2b4bdL,   0x298ccc36a3d7193bL,   0x922d5a7ed0c5161dL,   0xe4cd940be06728c4L,   0xef5cb80d23e73708L,   0x29c4fd6f93f61230L,
                0x4e30cf0507c74c09L,   0xc04c1b3d943d5ec6L,   0x03e1291945fdd157L,   0x11348fb5cb36dba1L,   0xc5fe692324a33b0eL,   0x499425f2fa87319cL,   0x587d2e1de3bf7a76L,   0x3d1a1d39600d94e4L,
                0x88019070c7baedfdL,   0x13733cc160299767L,   0xe3ede1160bc75684L,   0x44abbd60a47d8e20L,   0xc589a0633522cb00L,   0xe87815164ace93ccL,   0x6b9e5d20a12cfe3dL,   0x11371eeb584a4436L,
                0xa6df8d4bb44831c6L,   0x852c8c2a711eb439L,   0x6db68c03a9fb89f3L,   0xfc170e64ea76b5b0L,   0x8dbe0e5f805cad36L,   0x7530ac9c6cf68e35L,   0x891a338814ed7939L,   0xe8214b6bdb3206b1L,
                0xe4a66072c4497e62L,   0xfc14bb667f4ec9a0L,   0x5648857d9958ef6cL,   0xce2487ddb79e1facL,   0x49687ef7bfb13209L,   0x72f4723cf6652529L,   0xd291228d7308942bL,   0xf00de97de596928cL,
                0xf7017fc9a08bf910L,   0x1ab9c11568f592beL,   0xb48a4ece91c1b9d0L,   0x0bc340b19ed82b04L,   0x435d352b0bd8fcefL,   0x3544ffdbb90f5ceeL,   0xacb9b26c18141308L,   0xf0d3923e920d0c84L,
                0x67d95eee3d2892eeL,   0xcbbf9791dac6abfaL,   0x2107ca17eeb2d41fL,   0x0a15b8536117f7f8L,   0xe38efd17847c5965L,   0x299f455128902084L,   0xe3c19c842da0fc7fL,   0x438542355030a02bL,
                0x09b20bfda067adc3L,   0x207e8e2296b7b8c3L,   0xae2034d10df42664L,   0x8aec66374c6a4cafL,   0x021c5e382756df1fL,   0xdab397892e258d3fL,   0xbbeb27f2593ca22cL,   0x02f538557c761fbdL,
                0x5d1f93565bd28c1dL,   0xf93ce73599b8aa44L,   0x118489ef0e0ed804L,   0x26e9a60fc55ba1a7L,   0x2d592a941ee1bbcaL,   0xf3e4ea86bb639898L,   0x8a2c6f5594d4ef71L,   0xd3dd68b3e2e12b5dL,
                0xe3a3f757d7ee1599L,   0xa4c0e18d9997f82dL,   0xbd32a8c683cb1b29L,   0xa059953a4f92d812L,   0xbb2289a9855d888cL,   0x677d6ef341da321aL,   0x2b4ffc49b1821bd2L,   0x0257e7e26f413397L,
                0xcb31728801cb390cL,   0x3cb685b21cb3fba1L,   0x788db8a125d301bbL,   0x63bffa8112f19d42L,   0xa26082be05e4e1acL,   0x2fa9937f2125ab76L,   0xe5e315e2266c09bdL,   0xdc5b8b66d671f135L,
                0x7f354193fabcb03aL,   0x3c9d682d7f698313L,   0x8ba04039ff140fdcL,   0x312a0a394e8c9048L,   0x1a2290ecb9f91d01L,   0x28cd49e7af451ec0L,   0x0f6adbde5fffc10aL,   0xc53c8c75fa7dcf99L,
                0x01fc98ccb44ca6f3L,   0x6bd7a58209c968c0L,   0xac23bcfd1a4fa2e1L,   0x7fc86c6fb1b0e97cL,   0x9ed901f601eaf9f0L,   0x95f1081a1bebbf37L,   0xdb26cd0da39b1f05L,   0x4c6e73df5fb3f0faL,
                0x3eb86a198b26131cL,   0xcac5592422935ebdL,   0x95eacd29bf617efaL,   0x2f41a05effe82b79L,   0xa86a40ef4867cae7L,   0x9c39b9117a125986L,   0xe37d32ce39dbcb51L,   0x3f68378eb6844a13L,
                0x7cc5a27ca798f90cL,   0x0620a80357ec10a5L,   0xeb8432e5703111deL,   0xe859f372be354560L,   0x82656f21a2c57145L,   0x14a9b7e1c553ea68L,   0xd2d5dd6f9307bb8aL,   0x14b7194207b5105cL,
                0x8184d3c3a12ddc77L,   0x519f29673d8158ceL,   0xb3c32ca30f77e983L,   0x2128e5d7e296bbaaL,   0xb3c36f108c02701bL,   0x79799e52e875f1cfL,   0xfadffb023a68e76cL,   0xb092a17c4f389380L,
                0x26649815211577daL,   0x64df730e2b87a4fdL,   0x1a5e4f14169cfcf2L,   0xe076a65f976e635cL,   0xdcad57936e017e84L,   0x2123f4adcfe3e761L,   0x7689ce9c7291b34aL,   0x3128d6249bfef6afL,
                0xed98745fad9bcaa0L,   0xe48850a31635fb8bL,   0x06fd57bd0d326219L,   0x1746dfa4e85901e7L,   0xae9d5a4533d88a6dL,   0x21ea70902de52e47L,   0x711024d7735e27c4L,   0x8348e17f014190e7L,
                0xf6df0d50c6700128L,   0x5b70ecaba6a01c98L,   0x1114af3e1dd46fd6L,   0x1e3c56823076fa3dL,   0x642f2eb5a7c7c625L,   0x75655a99c51920cdL,   0xefc5e07d1c996040L,   0xe3048644ef5fc2baL,
                0xf381235f5959d426L,   0xb1485dbbf14bb82bL,   0x340ca2ab7e8c3151L,   0x5901bb9dd8c93107L,   0x1693701c2f0fd38aL,   0x2265d674ecc395fbL,   0xf951cbe74cde4af9L,   0x16de85e3e0cb3310L,
                0x8b16c0143a0106ffL,   0xf125b5b3cb45f407L,   0x79e7389f5cd3a367L,   0x5a80b1e4edb17199L,   0x436ea05a3e377949L,   0x3a3d4ecde00b34a0L,   0xffa49567f668fa93L,   0x36bcae2201e1c17cL,
                0xeac3650f973ad8d5L,   0x430dbb8d05f92104L,   0x5641edce3ac26afbL,   0x786aff702a2cacb4L,   0xf6228018eeb3e205L,   0x5223b6b884da7b94L,   0xf69cb1725661ced8L,   0x52d65674bb06447dL,
                0x10d976884a4d4e2eL,   0x85562963afb9fd77L,   0x3eb067c62eccb316L,   0xb715b82c4cd5704bL,   0xfc48c9515a696aaaL,   0x91ca3a2fc6c97b48L,   0x1e1227eeea5aae0fL,   0x1fce1b1b0149c632L,
                0xfdd8afd9f6466639L,   0x645338f3eb8392c8L,   0x3318915b53748398L,   0xbb711937afaa09e5L,   0x5fc32ff1b3c1fe1dL,   0xaca39dbe6f87b608L,   0xbed2b1b1c036c554L,   0x22daaf24caf4f53dL,
                0xf854e55a212471d9L,   0x7d2d07779b25563bL,   0x85ed851cdc95dbe4L,   0x6ff966162c13e934L,   0x0886ba4d85f776ecL,   0x4fc3757ccc791c7dL,   0x67171d83fe93e855L,   0x650428c5a5d69909L,
                0x1a4af2bc95b74227L,   0x26ae05e937cc6e58L,   0xb6ebf6a679fc9dbcL,   0x6a289f831db090a4L,   0xfed906d8873153d8L,   0x8d17068c2fcb255dL,   0x9ce6f36322e5f0e9L,   0x99505ec4777d1d28L,
                0xcea31a15fc3f4432L,   0x40ef079c4f26c32bL,   0xf9c2cb89f0b40d03L,   0x4f10dbc4bc83de6dL,   0xe34ae5cb8798ec34L,   0x632d8651cc6caf6bL,   0xce4797bd98ca8826L,   0xc28d82edc7bcd3b2L,
                0x2afb56ffb2280bf9L,   0x0faa53ba70bb13f1L,   0xb88c9bee75f865dbL,   0x65b9747600c27a47L,   0x7147367e52b391d3L,   0x9a10c6322889967aL,   0xd667521fe7e68d9fL,   0x41b14d505d608d8aL,
                0x2a8d5ee472197b7aL,   0x9e0d40e0b7d84d86L  };
    }

    private static class BlowfishCBC extends BlowfishECB {
        // here we hold the CBC IV
        BigInteger m_lCBCIV;

        /**
         * set the current CBC IV (for cipher resets)
         * @param lNewCBCIV the new CBC IV
         */
        public void setCBCIV(BigInteger lNewCBCIV) { m_lCBCIV = lNewCBCIV; }

        /**
         * set the current CBC IV (for cipher resets)
         * @param newCBCIV the new CBC IV  in network byte ordered array
         */
        public void setCBCIV(byte[] newCBCIV)
        {
            m_lCBCIV = byteArrayToBigInteger(newCBCIV, 0);
        }

        /**
         * constructor
         * @param bfkey key material, up to MAXKEYLENGTH bytes
         * @param lInitCBCIV the CBC IV
         */
        public BlowfishCBC(byte[] bfkey, BigInteger lInitCBCIV){
            super(bfkey);
            // store the CBCB IV
            setCBCIV(lInitCBCIV);
        }

        /**
         * cleans up all critical internals,
         * call this if you don't need an instance anymore
         */
        @Override
        public void cleanUp() {
            m_lCBCIV = new BigInteger("0");
            super.cleanUp();
        }

        // internal routine to encrypt a block in CBC mode
        private BigInteger encryptBlockCBC(BigInteger lPlainblock) {
            // chain with the CBC IV
            lPlainblock = lPlainblock.xor(m_lCBCIV);
            // encrypt the block
            lPlainblock = super.encryptBlock(lPlainblock);
            // the encrypted block is the new CBC IV
            return (m_lCBCIV = lPlainblock);
        }

        // internal routine to decrypt a block in CBC mode
        private BigInteger decryptBlockCBC(BigInteger lCipherblock) {
            // save the current block
            BigInteger lTemp = lCipherblock;
            // decrypt the block
            lCipherblock = super.decryptBlock(lCipherblock);
            // dechain the block
            lCipherblock = lCipherblock.xor(m_lCBCIV);
            // set the new CBC IV
            m_lCBCIV = lTemp;
            // return the decrypted block
            return lCipherblock;
        }

        /**
         * encrypts a byte buffer (should be aligned to an 8 byte border) to itself
         * @param buffer buffer to encrypt
         */
        @Override
        public void encrypt(byte[] buffer) {

            int nLen = buffer.length;
            BigInteger lTemp;
            for (int nI = 0; nI < nLen; nI +=16) {
                // encrypt a temporary 128bit block
                lTemp = byteArrayToBigInteger(buffer, nI);
                lTemp = encryptBlockCBC(lTemp);
                bigIntegerToByteArray(lTemp, buffer, nI);
            }
        }

        /**
         * decrypts a byte buffer (should be aligned to an 8 byte border) to itself
         * @param buffer buffer to decrypt
         */
        @Override
        public void  decrypt(byte[] buffer) {
            int nLen = buffer.length;
            BigInteger lTemp;
            for (int nI = 0; nI < nLen; nI +=16) {
                // decrypt over a temporary 128bit block
                lTemp = byteArrayToBigInteger(buffer, nI);
                lTemp = decryptBlockCBC(lTemp);
                bigIntegerToByteArray(lTemp, buffer, nI);
            }
        }

    }

    /**
     * gets bytes from an array into a long
     * @param buffer where to get the bytes
     * @param nStartIndex index from where to read the data
     * @return the 128bit integer
     */
    private static BigInteger byteArrayToBigInteger(byte[] buffer, int nStartIndex) {
        BigInteger twoFiftyFive = new BigInteger("255");
        return  new BigInteger(buffer[nStartIndex] +"").shiftLeft(120).or(
                new BigInteger(buffer[nStartIndex + 1] +"").and(twoFiftyFive).shiftLeft(112).or(
                        new BigInteger(buffer[nStartIndex + 2] +"").and(twoFiftyFive).shiftLeft(104).or(
                                new BigInteger(buffer[nStartIndex + 3] +"").and(twoFiftyFive).shiftLeft(96).or(
                                        new BigInteger(buffer[nStartIndex + 4] +"").and(twoFiftyFive).shiftLeft(88).or(
                                                new BigInteger(buffer[nStartIndex + 5] +"").and(twoFiftyFive).shiftLeft(80).or(
                                                        new BigInteger(buffer[nStartIndex + 6] +"").and(twoFiftyFive).shiftLeft(72).or(
                                                                new BigInteger(buffer[nStartIndex + 7] +"").and(twoFiftyFive).shiftLeft(64).or(
                                                                        new BigInteger(buffer[nStartIndex + 8] +"").and(twoFiftyFive).shiftLeft(56).or(
                                                                                new BigInteger(buffer[nStartIndex + 9] +"").and(twoFiftyFive).shiftLeft(48).or(
                                                                                        new BigInteger(buffer[nStartIndex + 10] +"").and(twoFiftyFive).shiftLeft(40).or(
                                                                                                new BigInteger(buffer[nStartIndex + 11] +"").and(twoFiftyFive).shiftLeft(32).or(
                                                                                                        new BigInteger(buffer[nStartIndex + 12] +"").and(twoFiftyFive).shiftLeft(24).or(
                                                                                                                new BigInteger(buffer[nStartIndex + 13] +"").and(twoFiftyFive).shiftLeft(16).or(
                                                                                                                        new BigInteger(buffer[nStartIndex + 14] +"").and(twoFiftyFive).shiftLeft(8).or(
                                                                                                                                new BigInteger(buffer[nStartIndex + 15] +"").and(twoFiftyFive))))))))))))))));

    }
    /**
     * converts a long o bytes which are put into a given array
     * @param lValue the 128bit integer to convert
     * @param buffer the target buffer
     * @param nStartIndex where to place the bytes in the buffer
     */
    private static void bigIntegerToByteArray(BigInteger lValue, byte[] buffer, int nStartIndex) {

        buffer[nStartIndex] = (lValue.shiftRight(120).byteValue());
        buffer[nStartIndex + 1] = (byte) (lValue.shiftRight(112).byteValue() & 0x0ff);
        buffer[nStartIndex + 2] = (byte) (lValue.shiftRight(104).byteValue() & 0x0ff);
        buffer[nStartIndex + 3] = (byte) (lValue.shiftRight(96).byteValue() & 0x0ff);
        buffer[nStartIndex + 4] = (byte) (lValue.shiftRight(88).byteValue() & 0x0ff);
        buffer[nStartIndex + 5] = (byte) (lValue.shiftRight(80).byteValue() & 0x0ff);
        buffer[nStartIndex + 6] = (byte) (lValue.shiftRight(72).byteValue() & 0x0ff);
        buffer[nStartIndex + 7] = (byte) (lValue.shiftRight(64).byteValue() & 0x0ff);
        buffer[nStartIndex + 8] = (byte) (lValue.shiftRight(56).byteValue() & 0x0ff);
        buffer[nStartIndex + 9] = (byte) (lValue.shiftRight(48).byteValue() & 0x0ff);
        buffer[nStartIndex + 10] = (byte) (lValue.shiftRight(40).byteValue() & 0x0ff);
        buffer[nStartIndex + 11] = (byte) (lValue.shiftRight(32).byteValue() & 0x0ff);
        buffer[nStartIndex + 12] = (byte) (lValue.shiftRight(24).byteValue() & 0x0ff);
        buffer[nStartIndex + 13] = (byte) (lValue.shiftRight(16).byteValue() & 0x0ff);
        buffer[nStartIndex + 14] = (byte) (lValue.shiftRight(8).byteValue() & 0x0ff);
        buffer[nStartIndex + 15] = (lValue.byteValue());
    }

    /**
     * converts values from an integer array to a long
     * @param buffer where to get the bytes
     * @param nStartIndex index from where to read the data
     * @return the 64bit integer
     */
    private static long intArrayToLong(int[] buffer, int nStartIndex) {
        return (((long) buffer[nStartIndex]) << 32) | (((long) buffer[nStartIndex + 1]) & 0x0ffffffffL);
    }
    /**
     * converts a long to integers which are put into a given array
     * @param lValue the 64bit integer to convert
     * @param buffer the target buffer
     * @param nStartIndex where to place the bytes in the buffer
     */
    private static void longToIntArray(long lValue, int[] buffer, int nStartIndex) {
        buffer[nStartIndex]     = (int) (lValue >>> 32);
        buffer[nStartIndex + 1] = (int) lValue;
    }

    /**
     * makes a BigInteger from two longs (treated signed)
     * @param nLo lower 64bits
     * @param nHi higher 64bits
     * @return the built BigInteger
     */
    private static BigInteger makeBigInteger(long nLo, long nHi) {

        return (BigInteger.valueOf(nHi).shiftLeft(64). or(BigInteger.
                valueOf(nLo).and(new BigInteger("ffffffffffffffff", 16))));

    }

    /**
     * gets the lower 32 bits of a long
     * @param lVal the long integer
     * @return lower 32 bits
     */
    private static long longLo64(BigInteger lVal) {
        return lVal.longValue();
    }
    /**
     * gets the higher 32 bits of a long
     * @param lVal the long integer
     * @return higher 32 bits
     */
    private static long longHi64(BigInteger lVal) {
        return lVal.shiftRight(64).longValue();
    }
    private static int longLo32(long lVal) {
        return (int)lVal;
    }
    /**
     * gets the higher 32 bits of a long
     * @param lVal the long integer
     * @return higher 32 bits
     */
    private static int longHi32(long lVal) {
        return (int)((lVal >>> 32));
    }
    // our table for binhex conversion
    final static char[] HEXTAB = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f' };

    /**
     * converts a byte array to a binhex string
     * @param data the byte array
     * @param nStartPos start index where to get the bytes
     * @param nNumOfBytes number of bytes to convert
     * @return the binhex string
     */
    private static String bytesToBinHex(byte[] data, int nStartPos, int nNumOfBytes) {
        StringBuilder sbuf = new StringBuilder();
        sbuf.setLength(nNumOfBytes << 1);

        int nPos = 0;
        for (int nI = 0; nI < nNumOfBytes; nI++) {
            sbuf.setCharAt(nPos++, HEXTAB[(data[nI + nStartPos] >> 4) & 0x0f]);
            sbuf.setCharAt(nPos++, HEXTAB[data[nI + nStartPos] & 0x0f]);
        }
        return sbuf.toString();
    }

    /**
     * converts a binhex string back into a byte array (invalid codes will be skipped)
     * @param sBinHex binhex string
     * @param data the target array
     * @param nSrcPos from which character in the string the conversion should begin,
     *                remember that (nSrcPos modulo 2) should equals 0 normally
     * @param nDstPos to store the bytes from which position in the array
     * @param nNumOfBytes number of bytes to extract
     * @return number of extracted bytes
     */
    private static int binHexToBytes(String sBinHex, byte[] data, int nSrcPos, int nDstPos, int nNumOfBytes) {
        // check for correct ranges
        int nStrLen = sBinHex.length();

        int nAvailBytes = (nStrLen - nSrcPos) >> 1;
        if (nAvailBytes < nNumOfBytes){
            nNumOfBytes = nAvailBytes;
        }

        int nOutputCapacity = data.length - nDstPos;
        if (nNumOfBytes > nOutputCapacity) {
            nNumOfBytes = nOutputCapacity;
        }

        // convert now
        int nResult = 0;
        for (int nI = 0; nI < nNumOfBytes; nI++) {
            byte bActByte = 0;
            boolean blConvertOK = true;
            for (int nJ = 0; nJ < 2; nJ++) {
                bActByte <<= 4;
                char cActChar = sBinHex.charAt(nSrcPos++);

                if ((cActChar >= 'a') && (cActChar <= 'f'))
                    bActByte |= (byte)(cActChar - 'a') + 10;
                else
                if ((cActChar >= '0') && (cActChar <= '9'))
                    bActByte |= (byte)(cActChar - '0');
                else
                    blConvertOK = false;
            }
            if (blConvertOK) {
                data[nDstPos++] = bActByte;
                nResult++;
            }
        }

        return nResult;
    }

    /**
     * converts a byte array into an UNICODE string
     * @param data the byte array
     * @param nStartPos where to begin the conversion
     * @param nNumOfBytes number of bytes to handle
     * @return the string
     */
    private static String byteArrayToUNCString(byte[] data, int nStartPos, int nNumOfBytes) {
        // we need two bytes for every character
        nNumOfBytes &= ~1;
        // enough bytes in the buffer?
        int nAvailCapacity = data.length - nStartPos;
        if (nAvailCapacity < nNumOfBytes){
            nNumOfBytes = nAvailCapacity;
        }

        StringBuilder sbuf = new StringBuilder();
        sbuf.setLength(nNumOfBytes >> 1);

        int nSBufPos = 0;
        while (nNumOfBytes > 0) {
            sbuf.setCharAt(nSBufPos++, (char)(((int)data[nStartPos] << 8) | ((int)data[nStartPos + 1] & 0x0ff)));
            nStartPos += 2;
            nNumOfBytes -= 2;
        }

        return sbuf.toString();
    }
}
