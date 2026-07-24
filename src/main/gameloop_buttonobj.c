#include "types.h"
#include "main/gameloop_api.h"

extern int gGameLoopButtonObjects[2];
extern u8 gGameLoopButtonObjectCount;

int getButtonObjects(int** p)
{
    *p = gGameLoopButtonObjects;
    return gGameLoopButtonObjectCount;
}
void removeButtonObject(u32 object)
{
    int* buttonObjects;
    int buttonObjectCount;
    int objectIndex;
    int removeIndex;

    removeIndex = -1;
    objectIndex = 0;
    buttonObjects = gGameLoopButtonObjects;
    buttonObjectCount = gGameLoopButtonObjectCount;
    for (; objectIndex < buttonObjectCount; objectIndex++)
    {
        if (buttonObjects[0] == object)
        {
            removeIndex = objectIndex;
            break;
        }
        buttonObjects++;
    }
    for (objectIndex = removeIndex; objectIndex < buttonObjectCount - 1; objectIndex++)
    {
        gGameLoopButtonObjects[objectIndex] = gGameLoopButtonObjects[objectIndex + 1];
    }
    gGameLoopButtonObjectCount--;
}
