#include<iostream>
#include "sha1.h"

using namespace std;

int main()
{
    string message = "abc";         // hash should be: "a9993e364706816aba3e25717850c26c9cd0d89d"
    SHA1 objSha(message, STRING);

    string digest;

    int res = objSha.getHashValue(digest);

    if(res == SUCCESS)
    {
        cout << digest;
    }

    cout << endl;

    return 0;
}