#ifndef MAIN_DLL_DLL_0241_DRAKORENERGY_H_
#define MAIN_DLL_DLL_0241_DRAKORENERGY_H_

#include "main/game_object.h"
#include "main/object_descriptor.h"

extern ObjectDescriptor12 gDrakorEnergyObjDescriptor;

typedef struct DrakorenergyPlacement
{
    u8 pad_0[0x8 - 0x0];
    f32 posX;
    f32 posY;
    f32 posZ;
    s32 mapId;
    u8 pad_18[0x19 - 0x18];
    u8 unk19;
    u8 pad_1A[0x1E - 0x1A];
    s8 unk1E;
    u8 pad_1F[0x20 - 0x1F];
    s16 gameBitId;
    u8 pad_22[0x24 - 0x22];
    s16 unk24;
    u8 pad_26[0x2B - 0x26];
    u8 unk2B;
    u8 pad_2C[0x2E - 0x2C];
    s8 unk2E;
    u8 pad_2F[0x30 - 0x2F];
} DrakorenergyPlacement;

int drakorenergy_setScale(int* obj);
void DrakorEnergy_func0B_nop(void);
int drakorenergy_getExtraSize(void);
int drakorenergy_getObjectTypeId(void);
void drakorenergy_free(void);
void drakorenergy_render(GameObject* obj, int p1, int p2, int p3, int p4, s8 visible);
void drakorenergy_hitDetect(void);
void drakorenergy_update(int obj);
void drakorenergy_init(int* obj, u8* init);
void drakorenergy_release(void);
void drakorenergy_initialise(void);

#endif
