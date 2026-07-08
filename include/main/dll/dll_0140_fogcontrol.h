#ifndef MAIN_DLL_DLL_0140_FOGCONTROL_H_
#define MAIN_DLL_DLL_0140_FOGCONTROL_H_

#include "global.h"

typedef struct FogcontrolPlacement
{
    u8 pad0[0x18 - 0x0];
    s16 enableGameBit;
    s16 flags;
    s16 fogTop;
    s16 fogBottom;
    s16 fogBase;
    s16 fogGreen;
    s16 fogRed;
    s16 unk26;
    s16 unk28;
    s16 unk2A;
    s16 unk2C;
    s16 unk2E;
    s16 unk30;
    s16 unk32;
    s16 unk34;
    s16 unk36;
    u16 unk38;
    u16 unk3A;
    u8 unk3C;
    u8 pad3D[0x3E - 0x3D];
    s16 unk3E;
    s16 unk40;
    s16 unk42;
    s16 unk44;
    s16 unk46;
} FogcontrolPlacement;

typedef struct FogControlState
{
    f32 blend;
    u8 on : 1;
    u8 full : 1;
    u8 rest : 6;
} FogControlState;

int FogControl_getExtraSize(void);
int FogControl_getObjectTypeId(void);
void FogControl_free(int obj);
void FogControl_hitDetect(void);
void FogControl_update(int obj);
void FogControl_init(int obj, FogcontrolPlacement* placement);

#endif /* MAIN_DLL_DLL_0140_FOGCONTROL_H_ */
