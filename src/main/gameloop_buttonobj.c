
#include "main/gameloop_internal.h"
#include "main/gameloop_api.h"

int getButtonObjects(GameObject*** p) {
    *p = gGameLoopButtonObjects;
    return gGameLoopButtonObjectCount;
}
void removeButtonObject(GameObject* object) {
    GameObject** buttonObjects;
    GameObject** dst;
    int buttonObjectCount;
    int objectIndex;
    int removeIndex;

    removeIndex = -1;
    objectIndex = 0;
    buttonObjects = gGameLoopButtonObjects;
    buttonObjectCount = gGameLoopButtonObjectCount;
    for (; objectIndex < buttonObjectCount; objectIndex++) {
        if (*buttonObjects == object) {
            removeIndex = objectIndex;
            break;
        }
        buttonObjects++;
    }
    dst = &gGameLoopButtonObjects[removeIndex];
    for (objectIndex = removeIndex; objectIndex < buttonObjectCount - 1; objectIndex++) {
        dst[0] = dst[1];
        dst++;
    }
    gGameLoopButtonObjectCount--;
}
