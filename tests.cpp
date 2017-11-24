#include<iostream>
#include<string>
#include "sha1.h"

using namespace std;

// Basic test 1
void test1()
{
    string message = "abc";
    string target_digest = "a9993e364706816aba3e25717850c26c9cd0d89d";
    string digest;

    SHA1 objSha(message, STRING);
    
    int res = objSha.getHashValue(digest);

    if(res == SUCCESS)
    {
        if(digest == target_digest)
        {
            cout << "[Test case 1]: PASSED. Hash: " << digest << endl;
        }
        else
        {
            cout << "[Test case 1]: Digest does not match" << endl;
        }
    }
    else
    {
        cout << "[Test case 1]: Internal error. Error code = " << objSha.getShaState() <<  endl;
    }
}

// Basic test 2
void test2()
{
    string message = "test";
    string target_digest = "a94a8fe5ccb19ba61c4c0873d391e987982fbbd3";
    string digest;

    SHA1 objSha(message, STRING);
    
    int res = objSha.getHashValue(digest);

    if(res == SUCCESS)
    {
        if(digest == target_digest)
        {
            cout << "[Test case 2]: PASSED. Hash: " << digest << endl;
        }
        else
        {
            cout << "[Test case 2]: Digest does not match" << endl;
        }
    }
    else
    {
        cout << "[Test case 2]: Internal error. Error code = " << objSha.getShaState() <<  endl;
    }
}

// Multiple blocks
void test3()
{
    string message = "abcdefghijhlmnopqrstuvwxyzabcdefghijhlmnopqrstuvwxyzabcdefghijhlmnopqrstuvwxyzabcdefghijhlmnopqrstuvwxyz";
    string target_digest = "0ff7f2e1df668e4e7f49b898e88c14ec8a24eb8b";
    string digest;

    SHA1 objSha(message, STRING);
    
    int res = objSha.getHashValue(digest);

    if(res == SUCCESS)
    {
        if(digest == target_digest)
        {
            cout << "[Test case 3]: PASSED. Hash: " << digest << endl;
        }
        else
        {
            cout << "[Test case 3]: Digest does not match" << endl;
        }
    }
    else
    {
        cout << "[Test case 3]: Internal error. Error code = " << objSha.getShaState() <<  endl;
    }
}
