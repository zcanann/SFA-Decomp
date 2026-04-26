#ifndef MAIN_DLL_FIREPIPE_H_
#define MAIN_DLL_FIREPIPE_H_

#include "ghidra_import.h"

typedef struct FirePipeExtra {
    int effectObjs[8];
    u8 effectCount;
    u8 pad21[0x24 - 0x21];
    u8 cycleTimer[4];
    u8 emitTimer[4];
    int subObj;
    int activeSpawn;
    int effectType;
    f32 effectScale;
    s16 clearVolumeA;
    s16 clearVolumeB;
    u8 effectMode;
    u8 flags;
    u8 pad42[0x44 - 0x42];
} FirePipeExtra;

typedef struct FirePipeMapData {
    u8 pad00[0x18];
    s8 modeX;
    u8 modeY;
    u8 pad1A[0x1C - 0x1A];
    s16 scale;
    s16 gameBit;
    s16 timer;
    u8 flags;
} FirePipeMapData;

typedef struct FirePipeObject {
    s16 modeX;
    s16 modeY;
    s16 resetTimer;
    u8 pad06[0x08 - 0x06];
    f32 scale;
    u8 pad0C[0x46 - 0x0C];
    s16 objectId;
    u8 pad48[0x4C - 0x48];
    void *objectDef;
    void *model;
    u8 pad54[0xAF - 0x54];
    u8 statusFlags;
    u8 padB0[0xB8 - 0xB0];
    FirePipeExtra *extra;
    undefined4 (*callback)(void);
} FirePipeObject;

int firepipe_getExtraSize(void);
undefined4 firepipe_stateCallback(void);
int firepipe_func08(void);
void firepipe_free(FirePipeObject *obj);
void firepipe_render(FirePipeObject *obj, int param_2, int param_3, int param_4, int param_5, char param_6);
void firepipe_update(FirePipeObject *obj);
void firepipe_init(FirePipeObject *obj, FirePipeMapData *mapData);

#endif /* MAIN_DLL_FIREPIPE_H_ */
