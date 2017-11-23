
#ifndef SHA1_H
#define SHA1_H

#include <cstdint>
#include <string>

#define hashSize 20

#define CircularShift(bits,word) \
                (((word) << (bits)) | ((word) >> (32-(bits))))

enum SHAState
{
    PROCESS,
    MESSAGE_TOO_LONG,
    CORRUPTED,
    COMPUTED
};

enum SHAResult
{
    SUCCESS,
    FAILURE
};

enum InputType
{
    STRING,
    FILENAME
};

class SHA1
{
    private:
        uint32_t messageDigest[hashSize/4];     /* 160-bit string; bit sequence of 5 words              */
        uint32_t roundConstants[4];             /* 128-bit string; bit sequence of 4 words              */
        uint8_t messageBlock[64];               /* 512-bit string; represented as sequence of 16 words  */

        uint32_t indexLow;
        uint32_t indexHigh;
        int_least16_t messageBlockIndex;

        int state;

        /* *
         * Reset the variables and state variables
         * */
        int reset();

        /* *
         * Used to get the next 512 bits of the message in message block
         * */
        int processMessageBlock();

        /* *
         * Message should be padde to an even 512 bits
         *  - First padding bit must be '1'
         *  - The last 64 bits represent the length of the original message
         *  - All the bits in between shoule be '0'
         * */
        int padMessageBlock();

        /* *
         * Providing input to create the SHA hash (not required if already provided through constructor)
         * */
        int input(const uint8_t *message, unsigned length);

    public:
        /* *
         * Constructors
         * */
        SHA1();
        SHA1(const std::string &message, InputType type);

        /* *
         * Description:
         *  Method to update the input for SHA1
         * Parameters:
         *  message: string message or name of the file
         *  type: the type of message (STRING or FILENAME)
         * */
        int updateInput(const std::string &message, InputType type);
        
        /* *
         * Description:
         *  Returns the SHA1 hash generated
         * Parameters:
         *  uint8_t array to be filled with generated hash value
         * Returns:
         *  SHAState 'COMPUTED' on successfull generation of hash
         * */
        int getHashValue(std::string &digest);
};

#endif