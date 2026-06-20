#ifndef MAIN_MAPEVENTTYPES_H_
#define MAIN_MAPEVENTTYPES_H_

#include "global.h"

typedef struct MapEventInterface {
    u8 pad00[0x1C];
    void (*savePoint)(int position, s16 angle, int flags, int map);
    void (*gotoSavegame)(void);
    void (*restartPoint)(void *position, s16 angle, int map, int flag);
    void (*gotoRestartPoint)(void);
    void (*clearRestartPoint)(void);
    int (*getRestartGameNotCleared)(void);
    u8 pad34[0x40 - 0x34];
    u8 (*getMapAct)(s32 mapId);
    void (*setMapAct)(int mapId, int act);
    void (*setMapActLut)(int value, int idx);
    u8 (*getObjGroupStatus)(int mapId, int shift);
    void (*setObjGroupStatus)(int mapId, int shift, int value);
    u16 (*getMapObjGroupBit)(int mapId);
    void (*updateObjGroups)(int mapId);
    u32 (*getObjGroups)(int mapId);
    void (*resetObjGroups)(int mapId);
    void (*addTime)(int id, f32 time);
    int (*shouldNotSaveTime)(int id);
    f32 (*getTime)(int id);
    void (*updateTimes)(void);
    u8 (*getCurChar)(void);
    void (*setCharacter)(u8 character);
    u8 pad7C[0x88 - 0x7C];
    u8 *(*getLast)(void);
    void *(*getCurCharacterState)(void);
    u8 *(*getCurCharPos)(void);
    u8 *(*getTrickyEnergy)(void);
} MapEventInterface;

extern MapEventInterface **gMapEventInterface;

STATIC_ASSERT(offsetof(MapEventInterface, savePoint) == 0x1C);
STATIC_ASSERT(offsetof(MapEventInterface, gotoSavegame) == 0x20);
STATIC_ASSERT(offsetof(MapEventInterface, restartPoint) == 0x24);
STATIC_ASSERT(offsetof(MapEventInterface, gotoRestartPoint) == 0x28);
STATIC_ASSERT(offsetof(MapEventInterface, clearRestartPoint) == 0x2C);
STATIC_ASSERT(offsetof(MapEventInterface, getRestartGameNotCleared) == 0x30);
STATIC_ASSERT(offsetof(MapEventInterface, getMapAct) == 0x40);
STATIC_ASSERT(offsetof(MapEventInterface, setMapAct) == 0x44);
STATIC_ASSERT(offsetof(MapEventInterface, setMapActLut) == 0x48);
STATIC_ASSERT(offsetof(MapEventInterface, getObjGroupStatus) == 0x4C);
STATIC_ASSERT(offsetof(MapEventInterface, setObjGroupStatus) == 0x50);
STATIC_ASSERT(offsetof(MapEventInterface, getMapObjGroupBit) == 0x54);
STATIC_ASSERT(offsetof(MapEventInterface, updateObjGroups) == 0x58);
STATIC_ASSERT(offsetof(MapEventInterface, getObjGroups) == 0x5C);
STATIC_ASSERT(offsetof(MapEventInterface, resetObjGroups) == 0x60);
STATIC_ASSERT(offsetof(MapEventInterface, addTime) == 0x64);
STATIC_ASSERT(offsetof(MapEventInterface, shouldNotSaveTime) == 0x68);
STATIC_ASSERT(offsetof(MapEventInterface, getTime) == 0x6C);
STATIC_ASSERT(offsetof(MapEventInterface, updateTimes) == 0x70);
STATIC_ASSERT(offsetof(MapEventInterface, getCurChar) == 0x74);
STATIC_ASSERT(offsetof(MapEventInterface, setCharacter) == 0x78);
STATIC_ASSERT(offsetof(MapEventInterface, getLast) == 0x88);
STATIC_ASSERT(offsetof(MapEventInterface, getCurCharacterState) == 0x8C);
STATIC_ASSERT(offsetof(MapEventInterface, getCurCharPos) == 0x90);
STATIC_ASSERT(offsetof(MapEventInterface, getTrickyEnergy) == 0x94);

#endif /* MAIN_MAPEVENTTYPES_H_ */
