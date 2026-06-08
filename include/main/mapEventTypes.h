#ifndef MAIN_MAPEVENTTYPES_H_
#define MAIN_MAPEVENTTYPES_H_

#include "global.h"

typedef struct MapEventInterface {
    u8 pad00[0x1C];
    void (*triggerEvent)(int mapId, int eventId, int value, int arg);
    u8 pad20[0x28 - 0x20];
    void (*finishCurrentEvent)(struct MapEventInterface *self);
    u8 pad2C[0x40 - 0x2C];
    u8 (*getMode)(s32 mapId);
    void (*setMode)(int mapId, int value);
    void (*setRomListSlot)(int mapId, int slot);
    u8 (*getAnimEvent)(int mapId, int eventId);
    void (*setAnimEvent)(int mapId, int eventId, int value);
    u8 pad54[0x58 - 0x54];
    void (*loadRomListObjects)(int slot);
    u32 (*getObjectLoadBits)(int mapId);
    u8 pad60[0x64 - 0x60];
    void (*startTimedEvent)(int eventId, f32 duration);
    int (*isTimedEventActive)(int eventId);
    f32 (*getTimedEventProgress)(int eventId);
    u8 pad70[0x74 - 0x70];
    u8 (*getPlayerNo)(void);
    u8 pad78[0x8C - 0x78];
    void *(*getState)(struct MapEventInterface *self);
    u8 *(*getWarpPos)(void);
    u8 *(*getProgressPtr)(void);
} MapEventInterface;

STATIC_ASSERT(offsetof(MapEventInterface, triggerEvent) == 0x1C);
STATIC_ASSERT(offsetof(MapEventInterface, finishCurrentEvent) == 0x28);
STATIC_ASSERT(offsetof(MapEventInterface, getMode) == 0x40);
STATIC_ASSERT(offsetof(MapEventInterface, setMode) == 0x44);
STATIC_ASSERT(offsetof(MapEventInterface, setRomListSlot) == 0x48);
STATIC_ASSERT(offsetof(MapEventInterface, getAnimEvent) == 0x4C);
STATIC_ASSERT(offsetof(MapEventInterface, setAnimEvent) == 0x50);
STATIC_ASSERT(offsetof(MapEventInterface, loadRomListObjects) == 0x58);
STATIC_ASSERT(offsetof(MapEventInterface, getObjectLoadBits) == 0x5C);
STATIC_ASSERT(offsetof(MapEventInterface, startTimedEvent) == 0x64);
STATIC_ASSERT(offsetof(MapEventInterface, isTimedEventActive) == 0x68);
STATIC_ASSERT(offsetof(MapEventInterface, getTimedEventProgress) == 0x6C);
STATIC_ASSERT(offsetof(MapEventInterface, getPlayerNo) == 0x74);
STATIC_ASSERT(offsetof(MapEventInterface, getState) == 0x8C);
STATIC_ASSERT(offsetof(MapEventInterface, getWarpPos) == 0x90);
STATIC_ASSERT(offsetof(MapEventInterface, getProgressPtr) == 0x94);

#endif /* MAIN_MAPEVENTTYPES_H_ */
