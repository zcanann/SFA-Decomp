#ifndef MAIN_MAPEVENT_H_
#define MAIN_MAPEVENT_H_

#include "ghidra_import.h"

typedef struct MapEventInterface {
    u8 pad00[0x1C];
    void (*triggerEvent)(int mapId, int eventId, int value, int arg);
    u8 pad20[0x28 - 0x20];
    void (*finishCurrentEvent)(struct MapEventInterface *self);
    u8 pad2C[0x40 - 0x2C];
    u8 (*getMode)(s32 mapId);
    void (*setMode)(int mapId, int value);
    u8 pad48[0x4C - 0x48];
    u8 (*getAnimEvent)(int mapId, int eventId);
    void (*setAnimEvent)(int mapId, int eventId, int value);
} MapEventInterface;

#endif /* MAIN_MAPEVENT_H_ */
