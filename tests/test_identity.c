#include "airngin_identity.h"
#include <assert.h>
#include <stdio.h>

int main(void)
{
    assert(airngin_identity_valid("VTRA0007617394", "VTRA"));
    assert(!airngin_identity_valid("VTRA000761739", "VTRA"));
    assert(!airngin_identity_valid("ABCD0007617394", "VTRA"));
    assert(!airngin_identity_valid("VTRA000761739X", "VTRA"));
    assert(!airngin_identity_valid("VTRA0007617394", "VT*A"));
    puts("identity tests passed");
    return 0;
}
