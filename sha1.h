/* *
 * Description:
 *  sha1.h consists of class definition for SHA1 which implements the Secure Hashing Algorithm (https://tools.ietf.org/html/rfc3174).
 * 
 *  Refer sha1.cpp for implementation of methods
 * */

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
        int_least16_t messageBlockIndex;        /* pointer to currently filled bits in the messageBlock */

        SHAState state;                         /* current state of the SHA-1 generation process        */

        /* *
         * Reset the variables and state variables
         * */
        int reset();

        /* *
         * Process the contents of the messageBlock as per SHA-1 algorithm
         * */
        int processMessageBlock();

        /* *
         * Message should be padded to an even 512 bits
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
         *  std::string digest to be filled with generated hash value
         * Returns:
         *  SHAResult 'SUCCESS' on successfull generation of hash; FAILURE otherwise;
         *  'state' can be checked for further info in case of failure
         * */
        int getHashValue(std::string &digest);
};

#endif