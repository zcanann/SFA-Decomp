#ifndef MAIN_DLL_DF_DLL_0230_DFPWALLBAR_H_
#define MAIN_DLL_DF_DLL_0230_DFPWALLBAR_H_

#include "ghidra_import.h"

typedef struct ChukaPlacement
{
    u8 pad0[0x8 - 0x0];
    f32 posX;      /* 0x08 */
    f32 posY;      /* 0x0C */
    f32 posZ;      /* 0x10 */
    s32 mapId;     /* 0x14: ObjPlacement-head map id (after posX/Y/Z) */
    s8 rotXByte;   /* 0x18 high byte of initial rotX (<<8) */
    u8 modeIndex;  /* 0x19 mode selector; copied to ChukaState.modeIndex (indexes gChukaModeTable) */
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
void chuka_free(int obj);
void chuka_render(void);
void chuka_hitDetect(struct GameObject* obj);
void chuka_update(int obj);

#endif /* MAIN_DLL_DF_DLL_0230_DFPWALLBAR_H_ */
