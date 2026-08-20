#ifndef MAIN_DLL_DF_DLL_0230_DFPWALLBAR_H_
#define MAIN_DLL_DF_DLL_0230_DFPWALLBAR_H_

#include "game/objects/object.h"
#include "types.h"
#include "game/objects/object_setup.h"

typedef struct ChukaPlacement
{
    ObjPlacement base;
    s8 rotXByte;   /* 0x18 high byte of initial rotX (<<8) */
    u8 rowIndex;    /* 0x19 index into the safe-floor-tile table */
    s16 rotZInit;  /* 0x1A initial rotZ */
    s16 barHeight; /* 0x1C model-scale height divisor (rootMotionScale) */
    s16 unk1E;
    s16 unk20;
    u8 pad22[0x24 - 0x22];
    s16 unk24;
    u8 pad26[0x2B - 0x26];
    u8 unk2B;
    u8 pad2C[0x2E - 0x2C];
    s8 unk2E;
    u8 pad2F[0x30 - 0x2F];
} ChukaPlacement;

int chuka_getExtraSize(void);
int chuka_getObjectTypeId(void);
void chuka_free(GameObject* obj);
void chuka_render(void);
void chuka_hitDetect(GameObject* obj);
void chuka_update(GameObject* obj);

#endif /* MAIN_DLL_DF_DLL_0230_DFPWALLBAR_H_ */
