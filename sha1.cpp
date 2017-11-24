/* *
 * Description:
 *  sha1.cpp consists of implementation of methods for SHA1 interface as defined in the sha1.h header file
 * */

#include <iomanip>
#include <sstream>
#include "sha1.h"

using namespace std;

SHA1::SHA1()
{
    SHA1::reset();
}

SHA1::SHA1(const std::string &message, InputType type)
{
    SHA1::reset();

    SHA1::updateInput(message, type);
}

int SHA1::reset()
{
    roundConstants[0]       = 0x5A827999;
    roundConstants[1]       = 0x6ED9EBA1;
    roundConstants[2]       = 0x8F1BBCDC;
    roundConstants[3]       = 0xCA62C1D6;

    indexLow                = 0;
    indexHigh               = 0;
    messageBlockIndex       = 0;

    messageDigest[0]        = 0x67452301;
    messageDigest[1]        = 0xEFCDAB89;
    messageDigest[2]        = 0x98BADCFE;
    messageDigest[3]        = 0x10325476;
    messageDigest[4]        = 0xC3D2E1F0;

    state                   = PROCESS;

    return SUCCESS;
}

/* *
 * Take input from client and update the message block using the SHA1::input method below
 * */
int SHA1::updateInput(const std::string &message, InputType type)
{
    if(type == STRING)
    {
        // Handle string
        const uint8_t *ptrMessage = (const uint8_t *)message.c_str();
        size_t length             = message.length();

        return SHA1::input(ptrMessage, length);
    }
    else
    {
        // TODO: Handle file
        return SUCCESS;
    }
}

/* *
 * Fill the message block using the input provided by the client
 * */
int SHA1::input(const uint8_t *message, unsigned length)
{
    if(!length)
        return SUCCESS;

    if(state != PROCESS)
        return FAILURE;

    while(length-- && state == PROCESS)
    {
        messageBlock[messageBlockIndex++] = (*message & 0xFF);

        indexLow += 8;

        if(indexLow == 0)
        {
            indexHigh++;

            if(indexHigh == 0)
            {
                // The message is too long
                state = MESSAGE_TOO_LONG;
            }
        }

        if(messageBlockIndex == 64)
        {
            // Process the message block as we have read 512 bits
            SHA1::processMessageBlock();
        }

        message++;
    }

    return (state == PROCESS) ? SUCCESS : FAILURE;
}

/* *
 * Process the message block and transforms the bits as per SHA-1 algorithm.
 * The message should be padded as a prerequisite
 * */
int SHA1::processMessageBlock()
{
    uint32_t A, B, C, D, E;         /* Word buffers */
    uint32_t W[80];                 /* Word sequence */

    A = messageDigest[0];
    B = messageDigest[1];
    C = messageDigest[2];
    D = messageDigest[3];
    E = messageDigest[4];

    //-------------------------------------------------------------------------------------------
    // Message scheduler [start]
    //-------------------------------------------------------------------------------------------

    // First 16 words (32 bits each) in the array come from the 512 bits in the messageBlock
    for(int  t = 0; t < 16; ++t)
    {
        W[t]  = messageBlock[t * 4] << 24;
        W[t] |= messageBlock[t * 4 + 1] << 16;
        W[t] |= messageBlock[t * 4 + 2] << 8;
        W[t] |= messageBlock[t * 4 + 3];
    }

    // for rounds 16 to 79
    for(int t = 16; t < 80; ++t)
    {
        W[t] = CircularShift(1, W[t-3] ^ W[t-8] ^ W[t-14] ^ W[t-16]);
    }

    //-------------------------------------------------------------------------------------------
    // Message scheduler [end]
    // Processing of message digest starts (5 stages with 20 rounds each)
    //-------------------------------------------------------------------------------------------

    /* *
     * Stage 1: Rounds 0 to 19
     * */
    for(int t = 0; t < 20; ++t)
    {
        uint32_t temp = CircularShift(5,A) + ((B & C) | ((~B) & D)) + E + W[t] + roundConstants[0];
        E = D;
        D = C;
        C = CircularShift(30,B);
        B = A;
        A = temp;
    }

    /* *
     * Stage 2: Rounds 20 to 39
     * */
    for(int t = 20; t < 40; ++t)
    {
        uint32_t temp = CircularShift(5,A) + (B ^ C ^ D) + E + W[t] + roundConstants[1];
        E = D;
        D = C;
        C = CircularShift(30,B);
        B = A;
        A = temp;
    }

    /* *
     * Stage 3: Rounds 40 to 59
     * */
    for(int t = 40; t < 60; ++t)
    {
        uint32_t temp = CircularShift(5,A) + ((B & C) | (B & D) | (C & D)) + E + W[t] + roundConstants[2];
        E = D;
        D = C;
        C = CircularShift(30,B);
        B = A;
        A = temp;
    }

    /* *
     * Stage 4: Rounds 60 to 79
     * */
    for(int t = 60; t < 80; ++t)
    {
        uint32_t temp = CircularShift(5,A) + (B ^ C ^ D) + E + W[t] + roundConstants[3];
        E = D;
        D = C;
        C = CircularShift(30,B);
        B = A;
        A = temp;
    }

    messageDigest[0] += A;
    messageDigest[1] += B;
    messageDigest[2] += C;
    messageDigest[3] += D;
    messageDigest[4] += E;

    // Done with the current message block contents. Reset the message block index to read next set of messages
    messageBlockIndex = 0;

    return SUCCESS;
}

/* *
* Perform message padding to make the message an even 512 bits
* */
int SHA1::padMessageBlock()
{
    if(messageBlockIndex > 55)
    {
        // The current message block is too small to hold the initial padding bits and length.
        // We will pad the block, process it, and continue padding the next message block
        messageBlock[messageBlockIndex++] = 0x80;

        while(messageBlockIndex < 64)
        {
            messageBlock[messageBlockIndex++] = 0;
        }

        SHA1::processMessageBlock();

        while(messageBlockIndex < 56)
        {
            messageBlock[messageBlockIndex++] = 0;
        }
    }
    else
    {
        messageBlock[messageBlockIndex++] = 0x80;

        while(messageBlockIndex < 56)
        {
            messageBlock[messageBlockIndex++] = 0;
        }
    }

    // Storing the message length as last 64 bits
    messageBlock[56] = indexHigh >> 24;
    messageBlock[57] = indexHigh >> 16;
    messageBlock[58] = indexHigh >> 8;
    messageBlock[59] = indexHigh;
    messageBlock[60] = indexLow >> 24;
    messageBlock[61] = indexLow >> 16;
    messageBlock[62] = indexLow >> 8;
    messageBlock[63] = indexLow;

    return SHA1::processMessageBlock();
}

/* *
* Transform the hash generated (as available in messageDigest) to string and return to the client
* */
int SHA1::getHashValue(std::string &digest)
{
    if(state != PROCESS)
    {
        return FAILURE;
    }

    if(state != COMPUTED)
    {
        SHA1::padMessageBlock();
        for(int i = 0; i < 64; ++i)
        {
            messageBlock[i] = 0;
        }

        indexLow    = 0;
        indexHigh   = 0;

        state       = COMPUTED;
    }

    std::ostringstream result;
    for (size_t i = 0; i < sizeof(messageDigest) / sizeof(messageDigest[0]); i++)
    {
        result << std::hex << std::setfill('0') << std::setw(8);
        result << messageDigest[i];
    }

    digest = result.str();

    return SUCCESS;
}