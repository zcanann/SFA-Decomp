#include "main/game_object.h"
#include "main/dll/chukchukstate_struct.h"
#include "main/audio/sfx_ids.h"
#include "main/dll/dll_00CA_mediumbasket.h"
#include "main/effect_interfaces.h"
#include "ghidra_import.h"
#include "main/obj_placement.h"
#include "main/dll/scarab.h"
#include "main/dll/baddie_state.h"
#include "main/mapEventTypes.h"
#include "main/objanim.h"
#include "main/objhits.h"
#include "main/objseq.h"

typedef struct MediumbasketUpdateDropStateState
{
    u8 pad0[0x4 - 0x0];
    s16 unk4;
    s16 unk6;
    u8 pad8[0x28 - 0x8];
    f32 unk28;
    f32 unk2C;
    f32 unk30;
    f32 unk34;
    u8 pad38[0x44 - 0x38];
    u8 unk44;
    u8 pad45[0x46 - 0x45];
    u16 unk46;
} MediumbasketUpdateDropStateState;

typedef struct MediumbasketUpdateHeightBlendStateState
{
    u8 pad0[0x4 - 0x0];
    s16 unk4;
    s16 unk6;
    u8 pad8[0x28 - 0x8];
    f32 unk28;
    f32 unk2C;
    f32 unk30;
    f32 unk34;
    u8 pad38[0x44 - 0x38];
    u8 unk44;
    u8 pad45[0x46 - 0x45];
    u16 unk46;
} MediumbasketUpdateHeightBlendStateState;

extern undefined8 FUN_80003494();
extern undefined4 FUN_80006a54();
extern u32 randomGetRange(int min, int max);
extern int FUN_80017a98();
extern undefined4 FUN_80017ac8();
extern undefined4 FUN_800305f8();
extern undefined8 ObjGroup_RemoveObject();
extern undefined4 ObjGroup_AddObject();
extern undefined8 ObjMsg_SendToObjects();
extern uint ObjPath_GetPointModelMtx();
extern undefined4 ObjPath_GetPointWorldPosition();
extern undefined4 FUN_8014d3d0();
extern undefined8 FUN_8014d4c8();
extern undefined4 FUN_8015a320();
extern undefined4 FUN_8015a6c0();
extern undefined4 FUN_80293f90();
extern undefined4 FUN_80294964();

extern undefined4 DAT_803dc990;
extern undefined4 DAT_803dc994;
extern undefined4 DAT_803dc998;
extern undefined4* DAT_803dd70c;
extern undefined4* DAT_803dd738;
extern u8 lbl_803DDA78;
extern u8 lbl_803DDA79;
extern f64 DOUBLE_803e3948;
extern f64 DOUBLE_803e39a0;
extern f64 DOUBLE_803e3a00;
extern f32 lbl_803DC074;
extern f32 lbl_803E3998;
extern f32 lbl_803E39A8;
extern f32 lbl_803E39AC;
extern f32 lbl_803E39B0;
extern f32 lbl_803E39B4;
extern f32 lbl_803E39B8;
extern f32 lbl_803E39BC;
extern f32 lbl_803E39C0;
extern f32 lbl_803E39C4;
extern f32 lbl_803E39C8;
extern f32 lbl_803E39CC;
extern f32 lbl_803E39D0;
extern f32 lbl_803E39D4;
extern f32 lbl_803E39D8;
extern f32 lbl_803E39DC;
extern f32 lbl_803E39E0;
extern f32 lbl_803E39E4;
extern f32 lbl_803E39E8;
extern f32 lbl_803E39EC;
extern f32 lbl_803E39F0;
extern f32 lbl_803E39F4;
extern f32 lbl_803E39F8;
extern f32 lbl_803E3A08;
extern f32 lbl_803E3A0C;
extern f32 lbl_803E3A10;
extern f32 lbl_803E3A14;
extern f32 lbl_803E3A18;
extern void* PTR_DAT_80320998;

#pragma scheduling on
#pragma peephole on
extern f32 lbl_803E2CD8;
extern f32 lbl_803E2D00;
extern f32 lbl_803E2D14;
extern f32 lbl_803E2D10;
extern f32 lbl_803E2D18;
extern f32 lbl_803E2D1C;
extern f32 lbl_803E2D20;
extern f32 lbl_803E2D24;
extern f32 lbl_803E2D28;
extern f32 lbl_803E2D2C;
extern f32 lbl_803E2D30;
extern f32 lbl_803E2D34;
extern f32 lbl_803E2D38;
extern f32 lbl_803E2D3C;
extern f32 lbl_803E2D40;
extern f32 lbl_803E2D44;
extern f32 lbl_803E2D48;
extern f32 lbl_803E2D4C;
extern f32 lbl_803E2D50;
extern f32 lbl_803E2D54;
extern f32 lbl_803E2D58;
extern f32 lbl_803E2D5C;
extern f32 lbl_803E2D60;
extern f32 lbl_803E2D84;
extern f32 lbl_803E2D88;
extern f32 lbl_803E2D8C;
extern f32 lbl_803E2D90;
extern f32 lbl_803E2D94;
extern f32 lbl_803E2D98;
extern f32 lbl_803E2D9C;
extern f32 lbl_803E2DA0;
extern f32 lbl_803E2DA4;
extern f32 lbl_803E2DA8;
extern f32 lbl_803E2DAC;
extern f32 lbl_803E2DB0;
extern f32 lbl_803E2DB4;
extern f32 timeDelta;
extern u8 framesThisStep;
extern f32 lbl_803E2CE8;
extern f32 lbl_803E2CEC;
extern f32 lbl_803E2CF0;
extern f32 lbl_803E2CF4;
extern f32 lbl_803E2CF8;
extern f32 lbl_803E2CFC;
extern int* Obj_GetActiveModel(int* obj);
extern void ObjModel_SetRenderCallback(int* model, void* cb);
extern void renderWhirlpool(void);
extern void Camera_DisableViewYOffset(void);
extern void fn_8003B5E0(int arg0, int arg1, int arg2, int arg3);
extern void fn_8015CE68(int obj, int state);
extern u8 gMediumBasketStateHandlersA[];
extern u8 gMediumBasketStateHandlersB[];
extern int Obj_GetPlayerObject(void);
extern void Sfx_PlayFromObject(int obj, int sfxId);
extern f32 sqrtf(f32 value);
extern u8 lbl_8031FDA0[];
extern u8 lbl_8031FE18[];
extern s16 lbl_8031FD80[];
extern s16 lbl_8031FD90[];
extern u8 lbl_8031FE38[];
extern u8 lbl_8031FE48[];
extern void Camera_EnableViewYOffset(void);
extern void CameraShake_SetAllMagnitudes(f32 magnitude);
extern void* memcpy(void* dst, const void* src, u32 size);
extern f32 mathSinf(f32 angle);
extern f32 mathCosf(f32 angle);
extern void Matrix_TransformPoint(void* mtx, f32* x, f32* y, f32* z);
extern void voxmaps_updateRoutePath(void* from, void* to);
extern u8 Obj_IsLoadingLocked(void);
extern void* Obj_AllocObjectSetup(int size, int type);
extern int* Obj_SetupObject(void* setup, int a, int b, int c, void* d);
STATIC_ASSERT(sizeof(ChukChukState) == 0x18);
STATIC_ASSERT(offsetof(ChukChukState, flags) == 0x12);
extern f32 sqrtf(f32);

void FUN_8015ad60(undefined8 param_1, double param_2, double param_3, undefined8 param_4,
                  undefined8 param_5, undefined8 param_6, undefined8 param_7, undefined8 param_8,
                  short* obj, int state)
{
    int entryOffset;
    uint roll;
    ObjHitsPriorityState* hitState;
    undefined4 in_r8;
    undefined4 in_r9;
    undefined4 in_r10;
    undefined* entryTable;
    undefined8 result;
    double scalar;

    entryTable = (&PTR_DAT_80320998)[(uint) * (ushort*)(state + 0x338) * 2];
    hitState = (ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState;
    hitState->hitVolumePriority = 10;
    hitState->hitVolumeId = 1;
    if (obj[0x50] == 0)
    {
        *(byte*)((int)obj + 0xaf) = *(byte*)((int)obj + 0xaf) | 8;
        ObjHits_DisableObject((int)obj);
    }
    else
    {
        *(byte*)((int)obj + 0xaf) = *(byte*)((int)obj + 0xaf) & 0xf7;
        ObjHits_EnableObject((int)obj);
    }
    if (((((GroundBaddieState*)state)->baddie.controlFlags & 0x80000000) != 0) && (((GroundBaddieState*)state)->
        baddie.seqEntryIndex < 2))
    {
        if ((*(short*)(state + 0x338) == 0) && (roll = randomGetRange(0, 0x14), 9 < (int)roll))
        {
            ((GroundBaddieState*)state)->baddie.seqEntryIndex = 7;
        }
        else
        {
            ((GroundBaddieState*)state)->baddie.seqEntryIndex = 1;
        }
        ((GroundBaddieState*)state)->baddie.controlFlags = ((GroundBaddieState*)state)->baddie.controlFlags |
            0x40000000;
    }
    if ((((GroundBaddieState*)state)->baddie.controlFlags & 0x40000000) != 0)
    {
        *(char*)&((GroundBaddieState*)state)->baddie.seqEntryIndex = *(char*)&((GroundBaddieState*)state)->baddie.
            seqEntryIndex + '\x01';
        if ((byte)(&DAT_803dc994)[*(ushort*)(state + 0x338)] < ((GroundBaddieState*)state)->baddie.seqEntryIndex)
        {
            ((GroundBaddieState*)state)->baddie.seqEntryIndex = (&DAT_803dc990)[*(ushort*)(state + 0x338)];
        }
        if (*(ushort*)(state + 0x2a0) < 4)
        {
            entryOffset = (uint)((GroundBaddieState*)state)->baddie.seqEntryIndex * 0xc;
            result = FUN_8014d4c8((double)*(float*)(entryTable + entryOffset), param_2, param_3, param_4, param_5,
                                 param_6, param_7, param_8, (int)obj, state,
                                 (uint)(byte)entryTable[entryOffset + 8], 0, 0, in_r8, in_r9, in_r10);
        }
        else
        {
            entryOffset = (uint)((GroundBaddieState*)state)->baddie.seqEntryIndex * 0xc;
            result = FUN_8014d4c8((double)*(float*)(entryTable + entryOffset), param_2, param_3, param_4, param_5,
                                 param_6, param_7, param_8, (int)obj, state,
                                 (uint)(byte)entryTable[entryOffset + 9], 0, 0, in_r8, in_r9, in_r10);
        }
        if (obj[0x50] == 9)
        {
            FUN_8015a320(result, param_2, param_3, param_4, param_5, param_6, param_7, param_8, (int)obj);
        }
        else if (obj[0x50] == 1)
        {
            roll = randomGetRange(0, (uint)((GroundBaddieState*)state)->baddie.inWhirlpoolGroup);
            randomGetRange(0xffff8000, 0x7fff);
            scalar = (double)FUN_80293f90();
            *(float*)(obj + 6) =
                (float)((double)(float)((double)CONCAT44(0x43300000, roll ^ 0x80000000) - DOUBLE_803e3948
                ) * scalar + (double)*(float*)(*(int*)(obj + 0x26) + 8));
            scalar = (double)FUN_80294964();
            *(float*)(obj + 10) =
                (float)((double)(float)((double)CONCAT44(0x43300000, roll ^ 0x80000000) - DOUBLE_803e3948
                ) * scalar + (double)*(float*)(*(int*)(obj + 0x26) + 0x10));
            FUN_8014d3d0(obj, state, 1, 0);
        }
    }
    FUN_8014d3d0(obj, state, (uint)(byte)(&DAT_803dc998)[*(ushort*)(state + 0x338)], 0);
    FUN_8015a6c0((uint)obj, state);
    return;
}

void FUN_8015b2d0(short* obj, int state)
{
    if (*(char*)(state + 0x33b) == '\0')
    {
        ObjGroup_AddObject((int)obj, 0x50);
        *(undefined*)(state + 0x33b) = 1;
    }
    ObjHits_SetHitVolumeSlot((int)obj, 10, 1, 0);
    *(undefined*)(*(int*)(obj + 0x2a) + 0x70) = 0;
    *obj = *obj + -0x100;
    return;
}

undefined4
FUN_8015b7f0(undefined8 param_1, double param_2, double param_3, undefined8 param_4, undefined8 param_5,
             undefined8 param_6, undefined8 param_7, undefined8 param_8, int obj, int state)
{
    short phase;
    float zeroVal;
    uint flagBits;
    undefined4 result;
    int extra;
    undefined8 copied;

    extra = *(int*)&((GameObject*)obj)->extra;
    if ((*(char*)(state + 0x346) == '\0') ||
        (flagBits = (**(code**)(*DAT_803dd738 + 0x18))((double)lbl_803E3998), (flagBits & 1) != 0))
    {
        if (*(char*)(state + 0x27b) == '\0')
        {
            phase = *(short*)(extra + 0x402);
            if (phase == 3)
            {
                (**(code**)(*DAT_803dd70c + 0x14))(obj, state, 4);
            }
            else if (phase == 4)
            {
                if ((*(float*)(state + 0x2c0) < lbl_803E39A8) && (*(char*)(state + 0x346) != '\0')
                )
                {
                    if (*(byte*)(extra + 0x406) < 0x33)
                    {
                        (**(code**)(*DAT_803dd70c + 0x14))(obj, state, 1);
                    }
                    else
                    {
                        (**(code**)(*DAT_803dd70c + 0x14))(obj, state, 0);
                    }
                }
            }
            else if (phase == 1)
            {
                return 8;
            }
        }
        else
        {
            (**(code**)(*DAT_803dd70c + 0x14))(obj, state, 0xb);
        }
        zeroVal = lbl_803E39AC;
        *(float*)(state + 0x290) = lbl_803E39AC;
        *(float*)(state + 0x28c) = zeroVal;
        FUN_80003494(extra + 0x35c, obj + 0xc, 0xc);
        copied = FUN_80003494(extra + 0x368, *(int*)(state + 0x2d0) + 0xc, 0xc);
        FUN_80006a54(copied, param_2, param_3, param_4, param_5, param_6, param_7, param_8);
        if (*(char*)(extra + 0x381) == '\0')
        {
            (**(code**)(*DAT_803dd70c + 0x1c))
            ((double)*(float*)(extra + 0x374), (double)*(float*)(extra + 0x37c),
             (double)lbl_803E39AC, (double)lbl_803E39AC, (double)lbl_803E39B0, obj,
             state);
        }
        else
        {
            (**(code**)(*DAT_803dd70c + 0x1c))
            ((double)*(float*)(extra + 0x374), (double)*(float*)(extra + 0x37c),
             (double)lbl_803E39B4, (double)lbl_803E39B8, (double)lbl_803E39B0, obj,
             state);
        }
        if ((0x78 < *(short*)(state + 0x32e)) &&
            (extra = (**(code**)(*DAT_803dd738 + 0x44))
            ((double)(float)((double)CONCAT44(0x43300000,
                                              (uint) * (ushort*)(extra + 0x3fe)) -
                 DOUBLE_803e39a0), obj, state, 1), extra != 0))
        {
            return 5;
        }
        result = 0;
    }
    else
    {
        result = 5;
    }
    return result;
}

undefined4
FUN_8015bc20(undefined8 param_1, undefined8 param_2, undefined8 param_3, undefined8 param_4,
             undefined8 param_5, undefined8 param_6, undefined8 param_7, undefined8 param_8, uint obj
             , int state)
{
    undefined4 in_r8;
    undefined4 in_r9;
    undefined4 in_r10;
    undefined8 msgResult;

    if (*(char*)(state + 0x27b) == '\0')
    {
        if (*(char*)(state + 0x346) != '\0')
        {
            msgResult = ObjMsg_SendToObjects(param_1, param_2, param_3, param_4, param_5, param_6, param_7, param_8, 0, 3,
                                         obj, 0xe0000, obj, in_r8, in_r9, in_r10);
            if (*(int*)&((GameObject*)obj)->anim.placementData == 0)
            {
                FUN_80017ac8(msgResult, param_2, param_3, param_4, param_5, param_6, param_7, param_8, obj);
                return 0;
            }
            return 4;
        }
    }
    else
    {
        (**(code**)(*DAT_803dd70c + 0x14))(obj, state, 0xd);
        *(undefined4*)(state + 0x2d0) = 0;
        *(undefined*)(state + 0x25f) = 0;
        *(undefined*)(state + 0x349) = 0;
        ObjHits_DisableObject(obj);
        *(byte*)&((GameObject*)obj)->anim.resetHitboxMode = *(byte*)&((GameObject*)obj)->anim.resetHitboxMode |
            8;
    }
    return 0;
}

undefined4
FUN_8015c00c(undefined8 param_1, double param_2, double param_3, undefined8 param_4, undefined8 param_5,
             undefined8 param_6, undefined8 param_7, undefined8 param_8, uint obj, int state,
             undefined4 param_11, undefined4 param_12, undefined4 param_13, undefined4 param_14,
             undefined4 param_15, undefined4 param_16)
{
    extern undefined4 FUN_80006824(); /* #57 */
    float blend;
    int player;
    int extra;
    double blendD;

    extra = *(int*)&((GameObject*)obj)->extra;
    *(undefined*)(state + 0x34d) = 3;
    *(float*)(state + 0x2a0) = lbl_803E39C0;
    blend = lbl_803E39AC;
    blendD = (double)lbl_803E39AC;
    *(float*)(state + 0x280) = lbl_803E39AC;
    *(float*)(state + 0x284) = blend;
    if (*(char*)(state + 0x27a) != '\0')
    {
        FUN_800305f8(blendD, param_2, param_3, param_4, param_5, param_6, param_7, param_8, obj, 1, 0, param_12,
                     param_13, param_14, param_15, param_16);
        *(undefined*)(state + 0x346) = 0;
    }
    if ((*(byte*)(state + 0x356) & 1) == 0)
    {
        player = FUN_80017a98();
        if (*(short*)(player + 0x46) == 0)
        {
            FUN_80006824(obj, SFXfox_treadwater322);
        }
        else
        {
            FUN_80006824(obj, SFXfoot_metal_run_2);
        }
        FUN_80006824(obj, SFXdoor_unlocked);
        FUN_80006824(obj, SFXkr_panting2);
        *(byte*)(state + 0x356) = *(byte*)(state + 0x356) | 1;
    }
    if (((*(byte*)(state + 0x356) & 2) == 0) && (lbl_803E39C4 < ((GameObject*)obj)->anim.currentMoveProgress))
    {
        FUN_80006824(obj, SFXdoor_creak);
        *(byte*)(state + 0x356) = *(byte*)(state + 0x356) | 2;
        (**(code**)(*DAT_803dd738 + 0x4c))(obj, (int)*(short*)(extra + 0x3f0), 0xffffffff, 0);
    }
    return 0;
}

undefined4
FUN_8015c1b4(undefined8 param_1, double param_2, double param_3, undefined8 param_4, undefined8 param_5,
             undefined8 param_6, undefined8 param_7, undefined8 param_8, int obj, int state,
             undefined4 param_11, undefined4 param_12, undefined4 param_13, undefined4 param_14,
             undefined4 param_15, undefined4 param_16)
{
    float blend;
    int extra;
    ObjHitsPriorityState* hitState;

    extra = *(int*)&((GameObject*)obj)->extra;
    hitState = (ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState;
    hitState->hitVolumePriority = 10;
    hitState->hitVolumeId = 1;
    ObjHits_RegisterActiveHitVolumeObject(obj);
    if (*(byte*)(extra + 0x406) < 0x33)
    {
        if (*(char*)(state + 0x27a) != '\0')
        {
            FUN_800305f8((double)lbl_803E39AC, param_2, param_3, param_4, param_5, param_6, param_7, param_8,
                         obj, 0xe, 0, param_12, param_13, param_14, param_15, param_16);
            *(undefined*)(state + 0x346) = 0;
        }
    }
    else if (*(char*)(state + 0x27a) != '\0')
    {
        FUN_800305f8((double)lbl_803E39AC, param_2, param_3, param_4, param_5, param_6, param_7, param_8,
                     obj, 4, 0, param_12, param_13, param_14, param_15, param_16);
        *(undefined*)(state + 0x346) = 0;
    }
    *(undefined*)(state + 0x34d) = 3;
    *(float*)(state + 0x2a0) = lbl_803E39C0;
    *(byte*)(*(int*)(extra + 0x40c) + 0x44) = *(byte*)(*(int*)(extra + 0x40c) + 0x44) | 0xc;
    blend = lbl_803E39AC;
    *(float*)(state + 0x280) = lbl_803E39AC;
    *(float*)(state + 0x284) = blend;
    if ((*(byte*)(extra + 0x404) & 2) == 0)
    {
        *(float*)(state + 0x280) = lbl_803E39C8 + ((GameObject*)obj)->anim.currentMoveProgress;
    }
    return 0;
}

undefined4
FUN_8015c3b4(undefined8 param_1, double param_2, double param_3, undefined8 param_4, undefined8 param_5,
             undefined8 param_6, undefined8 param_7, undefined8 param_8, int obj, int state,
             undefined4 param_11, undefined4 param_12, undefined4 param_13, undefined4 param_14,
             undefined4 param_15, undefined4 param_16)
{
    int control;

    control = *(int*)&((GameObject*)obj)->extra;
    if (*(char*)(state + 0x27a) == '\0')
    {
        if (*(char*)(state + 0x346) != '\0')
        {
            *(undefined2*)(control + 0x402) = 3;
        }
    }
    else
    {
        *(byte*)&((GameObject*)obj)->anim.resetHitboxMode = *(byte*)&((GameObject*)obj)->anim.resetHitboxMode |
            8;
        if (*(char*)(state + 0x27a) != '\0')
        {
            FUN_800305f8((double)lbl_803E39AC, param_2, param_3, param_4, param_5, param_6, param_7, param_8,
                         obj, 2, 0, param_12, param_13, param_14, param_15, param_16);
            *(undefined*)(state + 0x346) = 0;
        }
        *(undefined2*)(control + 0x402) = 2;
        *(undefined*)(state + 0x34d) = 1;
        *(float*)(state + 0x2a0) = lbl_803E39CC;
    }
    control = *(int*)(control + 0x40c);
    *(byte*)(control + 0x44) = *(byte*)(control + 0x44) | 4;
    if ((*(uint*)(state + 0x314) & 0x200) != 0)
    {
        *(uint*)(state + 0x314) = *(uint*)(state + 0x314) & 0xfffffdff;
        *(byte*)(control + 0x44) = *(byte*)(control + 0x44) | 0x10;
    }
    *(byte*)(control + 0x44) = *(byte*)(control + 0x44) | 0xc;
    *(undefined4*)(state + 0x280) = *(undefined4*)(obj + 0x98);
    return 0;
}

undefined4
FUN_8015c514(undefined8 param_1, double param_2, double param_3, undefined8 param_4, undefined8 param_5,
             undefined8 param_6, undefined8 param_7, undefined8 param_8, uint obj, int state,
             undefined4 param_11, undefined4 param_12, undefined4 param_13, undefined4 param_14,
             undefined4 param_15, undefined4 param_16)
{
    extern undefined4 FUN_80006824(); /* #57 */
    int control;

    control = *(int*)(*(int*)&((GameObject*)obj)->extra + 0x40c);
    *(byte*)(control + 0x44) = *(byte*)(control + 0x44) | 4;
    if (*(char*)(state + 0x27a) != '\0')
    {
        FUN_800305f8((double)lbl_803E39AC, param_2, param_3, param_4, param_5, param_6, param_7, param_8,
                     obj, 0, 0, param_12, param_13, param_14, param_15, param_16);
        *(undefined*)(state + 0x346) = 0;
    }
    if (*(char*)(state + 0x27a) != '\0')
    {
        FUN_80017a98();
        control = FUN_80017a98();
        if (*(short*)(control + 0x46) == 0)
        {
            FUN_80006824(obj, SFXfox_treadwater322);
        }
        else
        {
            FUN_80006824(obj, SFXfoot_metal_run_2);
        }
        FUN_80006824(obj, SFXkr_panting1);
    }
    *(undefined*)(state + 0x34d) = 3;
    *(float*)(state + 0x2a0) = lbl_803E39CC;
    *(float*)(state + 0x280) = lbl_803E39AC;
    return 0;
}

undefined4
FUN_8015c654(undefined8 param_1, double param_2, double param_3, undefined8 param_4, undefined8 param_5,
             undefined8 param_6, undefined8 param_7, undefined8 param_8, uint obj, int state,
             undefined4 param_11, undefined4 param_12, undefined4 param_13, undefined4 param_14,
             undefined4 param_15, undefined4 param_16)
{
    extern undefined4 FUN_80006824(); /* #57 */
    int control;
    int extra;

    extra = *(int*)&((GameObject*)obj)->extra;
    control = *(int*)(extra + 0x40c);
    *(byte*)(control + 0x44) = *(byte*)(control + 0x44) | 4;
    *(float*)(state + 0x2a0) = lbl_803E39D0;
    if (*(char*)(state + 0x27a) != '\0')
    {
        FUN_800305f8((double)lbl_803E39AC, param_2, param_3, param_4, param_5, param_6, param_7, param_8,
                     obj, 10, 0, param_12, param_13, param_14, param_15, param_16);
        *(undefined*)(state + 0x346) = 0;
    }
    *(undefined*)(state + 0x34d) = 1;
    if ((*(uint*)(state + 0x314) & 1) != 0)
    {
        control = *(int*)(extra + 0x40c);
        *(uint*)(state + 0x314) = *(uint*)(state + 0x314) & ~1;
        *(byte*)(control + 0x44) = *(byte*)(control + 0x44) | 2;
        FUN_80006824(obj, SFXsc_fox_commdown);
    }
    (**(code**)(*DAT_803dd70c + 0x30))((double)lbl_803DC074, obj, state, 4);
    return 0;
}

#pragma scheduling off
#pragma peephole off
int mediumbasket_updateOpenState(int obj, int p)
{
    extern undefined4 GameBit_Set(int eventId, int value); /* #57 */
    extern int* gPlayerInterface;
    extern f32 timeDelta;
    extern f32 lbl_803E2D14;
    extern f32 lbl_803E2D70;
    extern f32 lbl_803E2D74;
    extern f32 lbl_803E2D78;
    GroundBaddieState* sub;
    int sub_40c;
    ObjHitsPriorityState* hitState;

    sub = ((GameObject*)obj)->extra;
    sub_40c = *(int*)&sub->control;
    hitState = (ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState;
    hitState->flags |= 1;
    ((GroundBaddieState*)p)->baddie.physicsActive = 1;
    if (*(char*)&((GroundBaddieState*)p)->baddie.moveJustStartedA != '\0')
    {
        ObjAnim_SetCurrentMove(obj, 11, lbl_803E2D14, 0);
        *(s8*)&((GroundBaddieState*)p)->baddie.moveDone = 0;
    }
    if (*(char*)&((GroundBaddieState*)p)->baddie.moveJustStartedA != '\0')
    {
        GameBit_Set(sub->gameBitB, 1);
        *(u8*)&((GameObject*)obj)->anim.resetHitboxMode &= ~0x8;
        ((GameObject*)obj)->anim.alpha = 0xff;
        *(s8*)&((GroundBaddieState*)p)->baddie.unk34D = 1;
        ((GroundBaddieState*)p)->baddie.moveSpeed = lbl_803E2D70 + (f32)(u32)
        sub->aggression / lbl_803E2D74;
    }
    if (*(s8*)&((GroundBaddieState*)p)->baddie.moveDone != 0)
    {
        sub->targetState = 1;
    }
    {
        int v = *(int*)&((GroundBaddieState*)p)->baddie.eventFlags;
        if ((v & 0x200) != 0)
        {
            ((GroundBaddieState*)p)->baddie.eventFlags = v & ~0x200;
            *(u8*)(sub_40c + 0x44) |= 0x20;
        }
    }
    *(u8*)(sub_40c + 0x44) |= 0x4;
    if (((GameObject*)obj)->anim.currentMoveProgress < lbl_803E2D78)
    {
        *(u8*)(sub_40c + 0x44) |= 0x8;
    }
    (*(int (**)(int, int, f32, int))(*gPlayerInterface + 0x30))(obj, p, timeDelta, 4);
    return 0;
}

int mediumbasket_updateOpenHitState(int obj, int p)
{
    extern undefined4 GameBit_Set(int eventId, int value); /* #57 */
    extern int* gPlayerInterface;
    extern f32 timeDelta;
    extern f32 lbl_803E2D14;
    extern f32 lbl_803E2D78;
    extern f32 lbl_803E2D7C;
    extern f32 lbl_803E2D80;
    GroundBaddieState* sub;
    int sub_40c;

    sub = ((GameObject*)obj)->extra;
    sub_40c = *(int*)&sub->control;
    ((ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState)->flags |= 1;
    ((GroundBaddieState*)p)->baddie.physicsActive = 1;
    ((ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState)->hitVolumePriority = 9;
    ((ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState)->hitVolumeId = 1;
    ObjHits_RegisterActiveHitVolumeObject(obj);
    if (*(char*)&((GroundBaddieState*)p)->baddie.moveJustStartedA != '\0')
    {
        ObjAnim_SetCurrentMove(obj, 8, lbl_803E2D14, 0);
        *(s8*)&((GroundBaddieState*)p)->baddie.moveDone = 0;
    }
    if (*(char*)&((GroundBaddieState*)p)->baddie.moveJustStartedA != '\0')
    {
        GameBit_Set(sub->gameBitB, 1);
        *(u8*)&((GameObject*)obj)->anim.resetHitboxMode &= ~0x8;
        ((GameObject*)obj)->anim.alpha = 0xff;
        *(s8*)&((GroundBaddieState*)p)->baddie.unk34D = 1;
        ((GroundBaddieState*)p)->baddie.moveSpeed = lbl_803E2D7C + (f32)(u32)
        sub->aggression / lbl_803E2D80;
    }
    if (*(s8*)&((GroundBaddieState*)p)->baddie.moveDone != 0)
    {
        sub->targetState = 1;
    }
    {
        int v = *(int*)&((GroundBaddieState*)p)->baddie.eventFlags;
        if ((v & 0x200) != 0)
        {
            ((GroundBaddieState*)p)->baddie.eventFlags = v & ~0x200;
            *(u8*)(sub_40c + 0x44) |= 0x20;
        }
    }
    *(u8*)(sub_40c + 0x44) |= 0x4;
    if (((GameObject*)obj)->anim.currentMoveProgress < lbl_803E2D78)
    {
        *(u8*)(sub_40c + 0x44) |= 0x8;
    }
    (*(int (**)(int, int, f32, int))(*gPlayerInterface + 0x30))(obj, p, timeDelta, 4);
    return 0;
}

undefined4
#pragma scheduling on
#pragma peephole on
FUN_8015c7a0(undefined8 param_1, double param_2, double param_3, undefined8 param_4, undefined8 param_5,
             undefined8 param_6, undefined8 param_7, undefined8 param_8, int obj, int state,
             undefined4 param_11, undefined4 param_12, undefined4 param_13, undefined4 param_14,
             undefined4 param_15, undefined4 param_16)
{
    int control;

    control = *(int*)(*(int*)&((GameObject*)obj)->extra + 0x40c);
    *(byte*)(control + 0x44) = *(byte*)(control + 0x44) | 4;
    *(float*)(state + 0x2a0) = lbl_803E39D0;
    if (*(char*)(state + 0x27a) != '\0')
    {
        FUN_800305f8((double)lbl_803E39AC, param_2, param_3, param_4, param_5, param_6, param_7, param_8,
                     obj, 5, 0, param_12, param_13, param_14, param_15, param_16);
        *(undefined*)(state + 0x346) = 0;
    }
    *(undefined*)(state + 0x34d) = 1;
    (**(code**)(*DAT_803dd70c + 0x30))((double)lbl_803DC074, obj, state, 4);
    return 0;
}

undefined4
FUN_8015c8bc(undefined8 param_1, double param_2, double param_3, undefined8 param_4, undefined8 param_5,
             undefined8 param_6, undefined8 param_7, undefined8 param_8, int obj, int state,
             undefined4 param_11, undefined4 param_12, undefined4 param_13, undefined4 param_14,
             undefined4 param_15, undefined4 param_16)
{
    bool moveStarted;
    float moveProgress;
    int control;

    control = *(int*)(*(int*)&((GameObject*)obj)->extra + 0x40c);
    *(byte*)(control + 0x44) = *(byte*)(control + 0x44) | 0xc;
    moveStarted = *(char*)(state + 0x27a) != '\0';
    if (moveStarted)
    {
        if (moveStarted)
        {
            FUN_800305f8((double)lbl_803E39AC, param_2, param_3, param_4, param_5, param_6, param_7, param_8,
                         obj, 0xf, 0, param_12, param_13, param_14, param_15, param_16);
            *(undefined*)(state + 0x346) = 0;
        }
        *(undefined*)(state + 0x34d) = 1;
    }
    *(float*)(state + 0x2a0) = *(float*)(state + 0x2c0) / lbl_803E39D4;
    if (*(float*)(state + 0x2a0) <= lbl_803E39D8)
    {
        if (*(float*)(state + 0x2a0) < lbl_803E39D0)
        {
            *(float*)(state + 0x2a0) = lbl_803E39D0;
        }
    }
    else
    {
        *(float*)(state + 0x2a0) = lbl_803E39D8;
    }
    moveProgress = ((GameObject*)obj)->anim.currentMoveProgress;
    if (lbl_803E39BC <= moveProgress)
    {
        *(float*)(state + 0x280) = lbl_803E39DC * (lbl_803E39E0 - moveProgress);
    }
    else
    {
        *(float*)(state + 0x280) = lbl_803E39DC * moveProgress;
    }
    (**(code**)(*DAT_803dd70c + 0x30))((double)lbl_803DC074, obj, state, 4);
    return 0;
}

undefined4
FUN_8015ca54(undefined8 param_1, double param_2, double param_3, undefined8 param_4, undefined8 param_5,
             undefined8 param_6, undefined8 param_7, undefined8 param_8, int obj, int state,
             undefined4 param_11, undefined4 param_12, undefined4 param_13, undefined4 param_14,
             undefined4 param_15, undefined4 param_16)
{
    uint roll;
    int extra;
    ObjHitsPriorityState* hitState;

    extra = *(int*)&((GameObject*)obj)->extra;
    *(byte*)(*(int*)(extra + 0x40c) + 0x44) = *(byte*)(*(int*)(extra + 0x40c) + 0x44) | 4;
    hitState = (ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState;
    hitState->hitVolumePriority = 10;
    hitState->hitVolumeId = 1;
    ObjHits_RegisterActiveHitVolumeObject(obj);
    if (*(char*)(state + 0x27a) != '\0')
    {
        roll = randomGetRange(0, 2);
        lbl_803DDA79 = (undefined)roll;
        roll = randomGetRange(0, 1);
        if (roll == 0)
        {
            if (*(char*)(state + 0x27a) != '\0')
            {
                FUN_800305f8((double)lbl_803E39AC, param_2, param_3, param_4, param_5, param_6, param_7, param_8,
                             obj, 3, 0, param_12, param_13, param_14, param_15, param_16);
                *(undefined*)(state + 0x346) = 0;
            }
        }
        else if (*(char*)(state + 0x27a) != '\0')
        {
            FUN_800305f8((double)lbl_803E39AC, param_2, param_3, param_4, param_5, param_6, param_7, param_8,
                         obj, 7, 0, param_12, param_13, param_14, param_15, param_16);
            *(undefined*)(state + 0x346) = 0;
        }
        *(undefined*)(state + 0x34d) = 1;
        *(float*)(state + 0x2a0) =
            lbl_803E39E4 +
            (float)((double)CONCAT44(0x43300000, (uint) * (byte*)(extra + 0x406)) - DOUBLE_803e39a0) /
            lbl_803E39E8;
    }
    if ((*(byte*)(extra + 0x406) < 0x33) || ((*(byte*)(extra + 0x404) & 2) != 0))
    {
        *(float*)(state + 0x280) = lbl_803E39AC;
    }
    else if ((*(float*)(state + 0x2c0) <= lbl_803E39EC) || (*(char*)(state + 0x346) != '\0')
    )
    {
        *(float*)(state + 0x280) = lbl_803E39AC;
    }
    else
    {
        *(float*)(state + 0x280) = *(float*)(state + 0x2c0) / lbl_803E39EC - lbl_803E39E0;
        *(float*)(state + 0x280) =
            *(float*)(state + 0x280) *
            ((float)((double)CONCAT44(0x43300000, (uint) * (byte*)(extra + 0x406)) - DOUBLE_803e39a0) /
                lbl_803E39F0);
    }
    (**(code**)(*DAT_803dd70c + 0x30))((double)lbl_803DC074, obj, state, 4);
    return 0;
}

undefined4
FUN_8015cd2c(undefined8 param_1, double param_2, double param_3, undefined8 param_4, undefined8 param_5,
             undefined8 param_6, undefined8 param_7, undefined8 param_8, int obj, int state,
             undefined4 param_11, undefined4 param_12, undefined4 param_13, undefined4 param_14,
             undefined4 param_15, undefined4 param_16)
{
    uint roll;
    int extra;
    ObjHitsPriorityState* hitState;

    extra = *(int*)&((GameObject*)obj)->extra;
    *(byte*)(*(int*)(extra + 0x40c) + 0x44) = *(byte*)(*(int*)(extra + 0x40c) + 0x44) | 4;
    hitState = (ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState;
    hitState->hitVolumePriority = 10;
    hitState->hitVolumeId = 1;
    ObjHits_RegisterActiveHitVolumeObject(obj);
    if (*(char*)(state + 0x27a) != '\0')
    {
        roll = randomGetRange(0, 1);
        if (roll == 0)
        {
            lbl_803DDA78 = 3;
            if (*(char*)(state + 0x27a) != '\0')
            {
                FUN_800305f8((double)lbl_803E39AC, param_2, param_3, param_4, param_5, param_6, param_7, param_8,
                             obj, 10, 0, param_12, param_13, param_14, param_15, param_16);
                *(undefined*)(state + 0x346) = 0;
            }
        }
        else
        {
            roll = randomGetRange(0, 2);
            lbl_803DDA78 = (undefined)roll;
            if (*(char*)(state + 0x27a) != '\0')
            {
                FUN_800305f8((double)lbl_803E39AC, param_2, param_3, param_4, param_5, param_6, param_7, param_8,
                             obj, 6, 0, param_12, param_13, param_14, param_15, param_16);
                *(undefined*)(state + 0x346) = 0;
            }
        }
        *(undefined*)(state + 0x34d) = 1;
        *(float*)(state + 0x2a0) =
            lbl_803E39E4 +
            (float)((double)CONCAT44(0x43300000, (uint) * (byte*)(extra + 0x406)) - DOUBLE_803e39a0) /
            lbl_803E39E8;
    }
    if ((*(byte*)(extra + 0x406) < 0x33) || ((*(byte*)(extra + 0x404) & 2) != 0))
    {
        *(float*)(state + 0x280) = lbl_803E39AC;
    }
    else if ((*(float*)(state + 0x2c0) <= lbl_803E39EC) || (*(char*)(state + 0x346) != '\0')
    )
    {
        *(float*)(state + 0x280) = lbl_803E39AC;
    }
    else
    {
        *(float*)(state + 0x280) = *(float*)(state + 0x2c0) / lbl_803E39EC - lbl_803E39E0;
        *(float*)(state + 0x280) =
            *(float*)(state + 0x280) *
            ((float)((double)CONCAT44(0x43300000, (uint) * (byte*)(extra + 0x406)) - DOUBLE_803e39a0) /
                lbl_803E39F0);
    }
    (**(code**)(*DAT_803dd70c + 0x30))((double)lbl_803DC074, obj, state, 4);
    return 0;
}

undefined4
FUN_8015d00c(undefined8 param_1, double param_2, double param_3, undefined8 param_4, undefined8 param_5,
             undefined8 param_6, undefined8 param_7, undefined8 param_8, short* obj, int state,
             undefined4 param_11, undefined4 param_12, undefined4 param_13, undefined4 param_14,
             undefined4 param_15, undefined4 param_16)
{
    int control;
    int extra;

    extra = *(int*)(obj + 0x5c);
    if (*(char*)(state + 0x27a) != '\0')
    {
        FUN_800305f8((double)lbl_803E39AC, param_2, param_3, param_4, param_5, param_6, param_7, param_8,
                     obj, 9, 0, param_12, param_13, param_14, param_15, param_16);
        *(undefined*)(state + 0x346) = 0;
    }
    control = *(int*)(extra + 0x40c);
    *(byte*)(control + 0x44) = *(byte*)(control + 0x44) | 0xc;
    if (*(char*)(state + 0x27a) != '\0')
    {
        *(byte*)((int)obj + 0xaf) = *(byte*)((int)obj + 0xaf) | 8;
        *(undefined2*)(extra + 0x402) = 4;
    }
    *obj = (short)(int)(lbl_803E39F4 *
        (((float)((double)CONCAT44(0x43300000,
                                   (int)*(short*)(state + 0x336) ^ 0x80000000)
            - DOUBLE_803e3a00) * lbl_803DC074) / lbl_803E39F8) +
        (float)((double)CONCAT44(0x43300000, (int)*obj ^ 0x80000000) -
            DOUBLE_803e3a00));
    *(float*)(state + 0x2a0) = lbl_803E39D0;
    *(float*)(state + 0x280) = lbl_803E39E0;
    return 0;
}

undefined4
FUN_8015d19c(undefined8 param_1, double param_2, double param_3, undefined8 param_4, undefined8 param_5,
             undefined8 param_6, undefined8 param_7, undefined8 param_8, int obj, int state,
             undefined4 param_11, undefined4 param_12, undefined4 param_13, undefined4 param_14,
             undefined4 param_15, undefined4 param_16)
{
    int control;
    ObjHitsPriorityState* hitState;

    control = *(int*)(*(int*)&((GameObject*)obj)->extra + 0x40c);
    hitState = (ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState;
    hitState->hitVolumePriority = 10;
    hitState->hitVolumeId = 1;
    ObjHits_RegisterActiveHitVolumeObject(obj);
    if (*(char*)(state + 0x27a) != '\0')
    {
        *(undefined*)(state + 0x346) = 0;
    }
    if (*(char*)(state + 0x27a) != '\0')
    {
        FUN_800305f8((double)lbl_803E39AC, param_2, param_3, param_4, param_5, param_6, param_7, param_8,
                     obj, 4, 0, param_12, param_13, param_14, param_15, param_16);
        *(undefined*)(state + 0x346) = 0;
    }
    *(undefined*)(state + 0x34d) = 3;
    *(float*)(state + 0x2a0) = lbl_803E39C0;
    if ((*(uint*)(state + 0x314) & 0x200) != 0)
    {
        *(uint*)(state + 0x314) = *(uint*)(state + 0x314) & 0xfffffdff;
        *(byte*)(control + 0x44) = *(byte*)(control + 0x44) | 0x10;
    }
    *(byte*)(control + 0x44) = *(byte*)(control + 0x44) | 0xc;
    return 0;
}

undefined4
FUN_8015d324(undefined8 param_1, double param_2, double param_3, undefined8 param_4, undefined8 param_5,
             undefined8 param_6, undefined8 param_7, undefined8 param_8, int obj, int state,
             undefined4 param_11, undefined4 param_12, undefined4 param_13, undefined4 param_14,
             undefined4 param_15, undefined4 param_16)
{
    extern undefined4 GameBit_Set(int eventId, int value); /* #57 */
    int extra;
    ObjHitsPriorityState* hitState;

    extra = *(int*)&((GameObject*)obj)->extra;
    if ((*(short*)(state + 0x276) != 4) && (*(char*)(state + 0x27a) != '\0'))
    {
        FUN_800305f8((double)lbl_803E39AC, param_2, param_3, param_4, param_5, param_6, param_7, param_8,
                     obj, 0xe, 0, param_12, param_13, param_14, param_15, param_16);
        *(undefined*)(state + 0x346) = 0;
    }
    *(byte*)(*(int*)(extra + 0x40c) + 0x44) = *(byte*)(*(int*)(extra + 0x40c) + 0x44) | 0xc;
    if (*(char*)(state + 0x27a) != '\0')
    {
        hitState = (ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState;
        hitState->flags &= ~1;
        *(float*)(state + 0x2a0) = lbl_803E39D0;
        *(float*)(state + 0x280) = lbl_803E39AC;
    }
    if (*(char*)(state + 0x346) != '\0')
    {
        GameBit_Set((int)*(short*)(extra + 0x3f4), 0);
        FUN_800305f8((double)lbl_803E39AC, param_2, param_3, param_4, param_5, param_6, param_7, param_8,
                     obj, 8, 0, param_12, param_13, param_14, param_15, param_16);
        *(undefined4*)(state + 0x2d0) = 0;
        *(undefined*)(state + 0x25f) = 0;
        *(undefined*)(state + 0x349) = 0;
        *(undefined2*)(extra + 0x402) = 0;
        *(byte*)&((GameObject*)obj)->anim.resetHitboxMode = *(byte*)&((GameObject*)obj)->anim.resetHitboxMode |
            8;
    }
    return 0;
}

undefined4
FUN_8015d518(undefined8 param_1, double param_2, double param_3, undefined8 param_4, undefined8 param_5,
             undefined8 param_6, undefined8 param_7, undefined8 param_8, int obj, int state,
             undefined4 param_11, undefined4 param_12, undefined4 param_13, undefined4 param_14,
             undefined4 param_15, undefined4 param_16)
{
    extern undefined4 GameBit_Set(int eventId, int value); /* #57 */
    int control;
    int extra;
    ObjHitsPriorityState* hitState;

    extra = *(int*)&((GameObject*)obj)->extra;
    control = *(int*)(extra + 0x40c);
    hitState = (ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState;
    hitState->flags |= 1;
    *(undefined*)(state + 0x25f) = 1;
    if (*(char*)(state + 0x27a) != '\0')
    {
        FUN_800305f8((double)lbl_803E39AC, param_2, param_3, param_4, param_5, param_6, param_7, param_8,
                     obj, 0xb, 0, param_12, param_13, param_14, param_15, param_16);
        *(undefined*)(state + 0x346) = 0;
    }
    if (*(char*)(state + 0x27a) != '\0')
    {
        GameBit_Set((int)*(short*)(extra + 0x3f4), 1);
        *(byte*)&((GameObject*)obj)->anim.resetHitboxMode = *(byte*)&((GameObject*)obj)->anim.resetHitboxMode &
            0xf7;
        ((GameObject*)obj)->anim.alpha = 0xff;
        *(undefined*)(state + 0x34d) = 1;
        *(float*)(state + 0x2a0) =
            lbl_803E3A08 +
            (float)((double)CONCAT44(0x43300000, (uint) * (byte*)(extra + 0x406)) - DOUBLE_803e39a0) /
            lbl_803E3A0C;
    }
    if (*(char*)(state + 0x346) != '\0')
    {
        *(undefined2*)(extra + 0x402) = 1;
    }
    if ((*(uint*)(state + 0x314) & 0x200) != 0)
    {
        *(uint*)(state + 0x314) = *(uint*)(state + 0x314) & 0xfffffdff;
        *(byte*)(control + 0x44) = *(byte*)(control + 0x44) | 0x20;
    }
    *(byte*)(control + 0x44) = *(byte*)(control + 0x44) | 4;
    if (((GameObject*)obj)->anim.currentMoveProgress < lbl_803E3A10)
    {
        *(byte*)(control + 0x44) = *(byte*)(control + 0x44) | 8;
    }
    (**(code**)(*DAT_803dd70c + 0x30))((double)lbl_803DC074, obj, state, 4);
    return 0;
}

undefined4
FUN_8015d6ec(undefined8 param_1, double param_2, double param_3, undefined8 param_4, undefined8 param_5,
             undefined8 param_6, undefined8 param_7, undefined8 param_8, int obj, int state,
             undefined4 param_11, undefined4 param_12, undefined4 param_13, undefined4 param_14,
             undefined4 param_15, undefined4 param_16)
{
    extern undefined4 GameBit_Set(int eventId, int value); /* #57 */
    int control;
    int extra;
    ObjHitsPriorityState* hitState;

    extra = *(int*)&((GameObject*)obj)->extra;
    control = *(int*)(extra + 0x40c);
    hitState = (ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState;
    hitState->flags |= 1;
    *(undefined*)(state + 0x25f) = 1;
    hitState->hitVolumePriority = 9;
    hitState->hitVolumeId = 1;
    ObjHits_RegisterActiveHitVolumeObject(obj);
    if (*(char*)(state + 0x27a) != '\0')
    {
        FUN_800305f8((double)lbl_803E39AC, param_2, param_3, param_4, param_5, param_6, param_7, param_8,
                     obj, 8, 0, param_12, param_13, param_14, param_15, param_16);
        *(undefined*)(state + 0x346) = 0;
    }
    if (*(char*)(state + 0x27a) != '\0')
    {
        GameBit_Set((int)*(short*)(extra + 0x3f4), 1);
        *(byte*)&((GameObject*)obj)->anim.resetHitboxMode = *(byte*)&((GameObject*)obj)->anim.resetHitboxMode &
            0xf7;
        ((GameObject*)obj)->anim.alpha = 0xff;
        *(undefined*)(state + 0x34d) = 1;
        *(float*)(state + 0x2a0) =
            lbl_803E3A14 +
            (float)((double)CONCAT44(0x43300000, (uint) * (byte*)(extra + 0x406)) - DOUBLE_803e39a0) /
            lbl_803E3A18;
    }
    if (*(char*)(state + 0x346) != '\0')
    {
        *(undefined2*)(extra + 0x402) = 1;
    }
    if ((*(uint*)(state + 0x314) & 0x200) != 0)
    {
        *(uint*)(state + 0x314) = *(uint*)(state + 0x314) & 0xfffffdff;
        *(byte*)(control + 0x44) = *(byte*)(control + 0x44) | 0x20;
    }
    *(byte*)(control + 0x44) = *(byte*)(control + 0x44) | 4;
    if (((GameObject*)obj)->anim.currentMoveProgress < lbl_803E3A10)
    {
        *(byte*)(control + 0x44) = *(byte*)(control + 0x44) | 8;
    }
    (**(code**)(*DAT_803dd70c + 0x30))((double)lbl_803DC074, obj, state, 4);
    return 0;
}

void mediumbasket_spawnContactObject(int* obj, int* state);

#pragma scheduling off
void dll_CA_func0B(int obj, int message)
{
    extern int* gPlayerInterface; /* #57 */
    GroundBaddieState* state = ((GameObject*)obj)->extra;

    switch ((u8)message)
    {
    case 0x80:
        ((void (*)(int, int, int))((void**)*gPlayerInterface)[5])(obj, (int)state, 2);
        state->baddie.substate = 4;
        state->baddie.moveJustStartedB = 1;
        break;
    }
}

#pragma peephole off
int mediumbasket_stateHandlerB04(int obj, int state)
{
    extern int* gPlayerInterface; /* #57 */
    if ((s8)((GroundBaddieState*)state)->baddie.moveJustStartedB != 0)
    {
        ((void (*)(int, int, int))((void**)*gPlayerInterface)[5])(obj, state, 2);
    }
    return 0;
}

int mediumbasket_stateHandlerB03(int obj, int state)
{
    extern undefined4 GameBit_Set(int eventId, int value); /* #57 */
    GroundBaddieState* sub;

    if ((s8)((GroundBaddieState*)state)->baddie.moveJustStartedB != 0)
    {
        sub = ((GameObject*)obj)->extra;
        sub->unk405 = 0;
        GameBit_Set((s32)sub->gameBitB, 0);
        GameBit_Set((s32)sub->gameBitA, 1);
    }
    return 0;
}

int mediumbasket_stateHandlerB02(int obj, int state)
{
    extern int* gPlayerInterface; /* #57 */
    extern void Obj_FreeObject(int obj); /* #57 */
    if ((s8)((GroundBaddieState*)state)->baddie.moveJustStartedB != 0)
    {
        ((void (*)(int, int, int))((void**)*gPlayerInterface)[5])(obj, state, 0xd);
        *(int*)&((GroundBaddieState*)state)->baddie.targetObj = 0;
        ((GroundBaddieState*)state)->baddie.physicsActive = 0;
        ((GroundBaddieState*)state)->baddie.hasTarget = 0;
        ObjHits_DisableObject(obj);
        *(u8*)&((GameObject*)obj)->anim.resetHitboxMode |= 8;
    }
    else if ((s8)((GroundBaddieState*)state)->baddie.moveDone != 0)
    {
        ObjMsg_SendToObjects(0, 3, obj, 0xe0000, obj);
        if (((GameObject*)obj)->anim.placementData == NULL)
        {
            Obj_FreeObject(obj);
            return 0;
        }
        return 4;
    }
    return 0;
}

int mediumbasket_updateLandingState(int obj, int state)
{
    extern int* gBaddieControlInterface; /* #57 */
    GroundBaddieState* sub = ((GameObject*)obj)->extra;
    int player;
    f32 noBlend;

    ((GroundBaddieState*)state)->baddie.unk34D = 3;
    ((GroundBaddieState*)state)->baddie.moveSpeed = lbl_803E2D28;
    noBlend = lbl_803E2D14;
    ((GroundBaddieState*)state)->baddie.animSpeedA = noBlend;
    ((GroundBaddieState*)state)->baddie.animSpeedB = noBlend;
    if ((s8)((GroundBaddieState*)state)->baddie.moveJustStartedA != 0)
    {
        ObjAnim_SetCurrentMove(obj, 1, noBlend, 0);
        ((GroundBaddieState*)state)->baddie.moveDone = 0;
    }
    if ((((GroundBaddieState*)state)->baddie.moveEventFlags & 1) == 0)
    {
        player = Obj_GetPlayerObject();
        if (((GameObject*)player)->anim.seqId == 0) goto playGroundLandSound;
        Sfx_PlayFromObject(obj, SFXfoot_metal_run_2);
        goto playLandingExtras;
    playGroundLandSound:
        Sfx_PlayFromObject(obj, SFXfox_treadwater322);
    playLandingExtras:
        Sfx_PlayFromObject(obj, SFXdoor_unlocked);
        Sfx_PlayFromObject(obj, SFXkr_panting2);
        ((GroundBaddieState*)state)->baddie.moveEventFlags |= 1;
    }
    if ((((GroundBaddieState*)state)->baddie.moveEventFlags & 2) == 0 && ((GameObject*)obj)->anim.currentMoveProgress >
        lbl_803E2D2C)
    {
        Sfx_PlayFromObject(obj, SFXdoor_creak);
        ((GroundBaddieState*)state)->baddie.moveEventFlags |= 2;
        ((void (*)(int, int, int, int))((void**)*gBaddieControlInterface)[19])(
            obj, (s32)sub->unk3F0, -1, 0);
    }
    return 0;
}

int mediumbasket_updateContactHitState(int obj, int state)
{
    GroundBaddieState* sub = ((GameObject*)obj)->extra;
    int control;
    f32 noBlend;

    ((ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState)->hitVolumePriority = 10;
    ((ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState)->hitVolumeId = 1;
    ObjHits_RegisterActiveHitVolumeObject(obj);
    if (sub->aggression > 0x32)
    {
        if ((s8)((GroundBaddieState*)state)->baddie.moveJustStartedA != 0)
        {
            ObjAnim_SetCurrentMove(obj, 4, lbl_803E2D14, 0);
            ((GroundBaddieState*)state)->baddie.moveDone = 0;
        }
    }
    else if ((s8)((GroundBaddieState*)state)->baddie.moveJustStartedA != 0)
    {
        ObjAnim_SetCurrentMove(obj, 0xe, lbl_803E2D14, 0);
        ((GroundBaddieState*)state)->baddie.moveDone = 0;
    }
    ((GroundBaddieState*)state)->baddie.unk34D = 3;
    ((GroundBaddieState*)state)->baddie.moveSpeed = lbl_803E2D28;
    control = *(int*)&sub->control;
    *(u8*)(control + 0x44) |= 0xc;
    noBlend = lbl_803E2D14;
    ((GroundBaddieState*)state)->baddie.animSpeedA = noBlend;
    ((GroundBaddieState*)state)->baddie.animSpeedB = noBlend;
    if ((sub->configFlags & 2) == 0)
    {
        ((GroundBaddieState*)state)->baddie.animSpeedA = lbl_803E2D30 + ((GameObject*)obj)->anim.currentMoveProgress;
    }
    return 0;
}

int mediumbasket_stateHandlerA0B(int obj, int state)
{
    GroundBaddieState* sub = ((GameObject*)obj)->extra;
    int control;

    if ((s8)((GroundBaddieState*)state)->baddie.moveJustStartedA != 0)
    {
        *(u8*)&((GameObject*)obj)->anim.resetHitboxMode |= 8;
        if ((s8)((GroundBaddieState*)state)->baddie.moveJustStartedA != 0)
        {
            ObjAnim_SetCurrentMove(obj, 2, lbl_803E2D14, 0);
            ((GroundBaddieState*)state)->baddie.moveDone = 0;
        }
        sub->targetState = 2;
        ((GroundBaddieState*)state)->baddie.unk34D = 1;
        ((GroundBaddieState*)state)->baddie.moveSpeed = lbl_803E2D34;
    }
    else
    {
        if ((s8)((GroundBaddieState*)state)->baddie.moveDone != 0)
        {
            sub->targetState = 3;
        }
    }
    control = *(int*)&sub->control;
    *(u8*)(control + 0x44) |= 4;
    if ((s32)(((GroundBaddieState*)state)->baddie.eventFlags & 0x200) != 0)
    {
        ((GroundBaddieState*)state)->baddie.eventFlags &= ~0x200;
        *(u8*)(control + 0x44) |= 0x10;
    }
    *(u8*)(control + 0x44) |= 0xc;
    ((GroundBaddieState*)state)->baddie.animSpeedA = ((GameObject*)obj)->anim.currentMoveProgress;
    return 0;
}

int mediumbasket_updateDropState(int obj, int state)
{
    int control = *(int*)(*(int*)&((GameObject*)obj)->extra + 0x40c);
    int player;

    ((MediumbasketUpdateDropStateState*)control)->unk44 |= 4;
    if ((s8)((GroundBaddieState*)state)->baddie.moveJustStartedA != 0)
    {
        ObjAnim_SetCurrentMove(obj, 0, lbl_803E2D14, 0);
        ((GroundBaddieState*)state)->baddie.moveDone = 0;
    }
    if ((s8)((GroundBaddieState*)state)->baddie.moveJustStartedA != 0)
    {
        Obj_GetPlayerObject();
        player = Obj_GetPlayerObject();
        if (((GameObject*)player)->anim.seqId == 0) goto playGroundDropSound;
        Sfx_PlayFromObject(obj, SFXfoot_metal_run_2);
        goto playDropExtras;
    playGroundDropSound:
        Sfx_PlayFromObject(obj, SFXfox_treadwater322);
    playDropExtras:
        Sfx_PlayFromObject(obj, SFXkr_panting1);
    }
    ((GroundBaddieState*)state)->baddie.unk34D = 3;
    ((GroundBaddieState*)state)->baddie.moveSpeed = lbl_803E2D34;
    ((GroundBaddieState*)state)->baddie.animSpeedA = lbl_803E2D14;
    return 0;
}

int mediumbasket_updateCommDownState(int obj, int state)
{
    extern int* gPlayerInterface; /* #57 */
    GroundBaddieState* sub = ((GameObject*)obj)->extra;
    int control = *(int*)&sub->control;

    *(u8*)(control + 0x44) |= 4;
    ((GroundBaddieState*)state)->baddie.moveSpeed = lbl_803E2D38;
    if ((s8)((GroundBaddieState*)state)->baddie.moveJustStartedA != 0)
    {
        ObjAnim_SetCurrentMove(obj, 10, lbl_803E2D14, 0);
        ((GroundBaddieState*)state)->baddie.moveDone = 0;
    }
    ((GroundBaddieState*)state)->baddie.unk34D = 1;
    if ((*(s32*)&((GroundBaddieState*)state)->baddie.eventFlags & 1) != 0)
    {
        control = *(int*)&sub->control;
        ((GroundBaddieState*)state)->baddie.eventFlags &= ~1;
        *(u8*)(control + 0x44) |= 2;
        Sfx_PlayFromObject(obj, SFXsc_fox_commdown);
    }
    ((void (*)(int, int, f32, int))((void**)*gPlayerInterface)[12])(obj, state, timeDelta, 4);
    return 0;
}

int mediumbasket_updateHeightBlendState(int obj, int state)
{
    extern int* gPlayerInterface; /* #57 */
    int control = *(int*)(*(int*)&((GameObject*)obj)->extra + 0x40c);
    f32 height;

    ((MediumbasketUpdateHeightBlendStateState*)control)->unk44 |= 0xc;
    if ((s8)((GroundBaddieState*)state)->baddie.moveJustStartedA != 0)
    {
        if ((s8)((GroundBaddieState*)state)->baddie.moveJustStartedA != 0)
        {
            ObjAnim_SetCurrentMove(obj, 0xf, lbl_803E2D14, 0);
            ((GroundBaddieState*)state)->baddie.moveDone = 0;
        }
        ((GroundBaddieState*)state)->baddie.unk34D = 1;
    }
    ((GroundBaddieState*)state)->baddie.moveSpeed = ((GroundBaddieState*)state)->baddie.targetDistance / lbl_803E2D3C;
    if (((GroundBaddieState*)state)->baddie.moveSpeed > lbl_803E2D40)
    {
        ((GroundBaddieState*)state)->baddie.moveSpeed = lbl_803E2D40;
    }
    else if (((GroundBaddieState*)state)->baddie.moveSpeed < lbl_803E2D38)
    {
        ((GroundBaddieState*)state)->baddie.moveSpeed = lbl_803E2D38;
    }
    height = ((GameObject*)obj)->anim.currentMoveProgress;
    if (height < lbl_803E2D24)
    {
        ((GroundBaddieState*)state)->baddie.animSpeedA = lbl_803E2D44 * height;
    }
    else
    {
        ((GroundBaddieState*)state)->baddie.animSpeedA = lbl_803E2D44 * (lbl_803E2D48 - height);
    }
    ((void (*)(int, int, f32, int))((void**)*gPlayerInterface)[12])(obj, state, timeDelta, 4);
    return 0;
}

int mediumbasket_stateHandlerA06(int obj, int state)
{
    extern int* gPlayerInterface; /* #57 */
    GroundBaddieState* sub = ((GameObject*)obj)->extra;
    int choice;

    *(u8*)(*(int*)&sub->control + 0x44) |= 4;
    ((ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState)->hitVolumePriority = 10;
    ((ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState)->hitVolumeId = 1;
    ObjHits_RegisterActiveHitVolumeObject(obj);
    if ((s8)((GroundBaddieState*)state)->baddie.moveJustStartedA != 0)
    {
        lbl_803DDA79 = randomGetRange(0, 2);
        choice = randomGetRange(0, 1);
        if (choice != 0)
        {
            if ((s8)((GroundBaddieState*)state)->baddie.moveJustStartedA != 0)
            {
                ObjAnim_SetCurrentMove(obj, 7, lbl_803E2D14, 0);
                ((GroundBaddieState*)state)->baddie.moveDone = 0;
            }
        }
        else
        {
            if ((s8)((GroundBaddieState*)state)->baddie.moveJustStartedA != 0)
            {
                ObjAnim_SetCurrentMove(obj, 3, lbl_803E2D14, 0);
                ((GroundBaddieState*)state)->baddie.moveDone = 0;
            }
        }
        ((GroundBaddieState*)state)->baddie.unk34D = 1;
        ((GroundBaddieState*)state)->baddie.moveSpeed = lbl_803E2D4C + (f32)sub->aggression / lbl_803E2D50;
    }
    if (sub->aggression > 50 && (sub->configFlags & 2) == 0)
    {
        if (((GroundBaddieState*)state)->baddie.targetDistance > lbl_803E2D54 &&
            (s8)((GroundBaddieState*)state)->baddie.moveDone == 0)
        {
            ((GroundBaddieState*)state)->baddie.animSpeedA = ((GroundBaddieState*)state)->baddie.targetDistance /
                lbl_803E2D54 - lbl_803E2D48;
            ((GroundBaddieState*)state)->baddie.animSpeedA =
                ((GroundBaddieState*)state)->baddie.animSpeedA * ((f32)sub->aggression / lbl_803E2D58);
        }
        else
        {
            ((GroundBaddieState*)state)->baddie.animSpeedA = lbl_803E2D14;
        }
    }
    else
    {
        ((GroundBaddieState*)state)->baddie.animSpeedA = lbl_803E2D14;
    }
    ((void (*)(int, int, f32, int))((void**)*gPlayerInterface)[12])(obj, state, timeDelta, 4);
    return 0;
}

int mediumbasket_stateHandlerA05(int obj, int state)
{
    extern int* gPlayerInterface; /* #57 */
    GroundBaddieState* sub = ((GameObject*)obj)->extra;
    int choice;

    *(u8*)(*(int*)&sub->control + 0x44) |= 4;
    ((ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState)->hitVolumePriority = 10;
    ((ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState)->hitVolumeId = 1;
    ObjHits_RegisterActiveHitVolumeObject(obj);
    if ((s8)((GroundBaddieState*)state)->baddie.moveJustStartedA != 0)
    {
        choice = randomGetRange(0, 1);
        if (choice != 0)
        {
            lbl_803DDA78 = randomGetRange(0, 2);
            if ((s8)((GroundBaddieState*)state)->baddie.moveJustStartedA != 0)
            {
                ObjAnim_SetCurrentMove(obj, 6, lbl_803E2D14, 0);
                ((GroundBaddieState*)state)->baddie.moveDone = 0;
            }
        }
        else
        {
            lbl_803DDA78 = 3;
            if ((s8)((GroundBaddieState*)state)->baddie.moveJustStartedA != 0)
            {
                ObjAnim_SetCurrentMove(obj, 10, lbl_803E2D14, 0);
                ((GroundBaddieState*)state)->baddie.moveDone = 0;
            }
        }
        ((GroundBaddieState*)state)->baddie.unk34D = 1;
        ((GroundBaddieState*)state)->baddie.moveSpeed = lbl_803E2D4C + (f32)sub->aggression / lbl_803E2D50;
    }
    if (sub->aggression > 50 && (sub->configFlags & 2) == 0)
    {
        if (((GroundBaddieState*)state)->baddie.targetDistance > lbl_803E2D54 &&
            (s8)((GroundBaddieState*)state)->baddie.moveDone == 0)
        {
            ((GroundBaddieState*)state)->baddie.animSpeedA = ((GroundBaddieState*)state)->baddie.targetDistance /
                lbl_803E2D54 - lbl_803E2D48;
            ((GroundBaddieState*)state)->baddie.animSpeedA =
                ((GroundBaddieState*)state)->baddie.animSpeedA * ((f32)sub->aggression / lbl_803E2D58);
        }
        else
        {
            ((GroundBaddieState*)state)->baddie.animSpeedA = lbl_803E2D14;
        }
    }
    else
    {
        ((GroundBaddieState*)state)->baddie.animSpeedA = lbl_803E2D14;
    }
    ((void (*)(int, int, f32, int))((void**)*gPlayerInterface)[12])(obj, state, timeDelta, 4);
    return 0;
}

int mediumbasket_updateSpinState(int obj, int state)
{
    GroundBaddieState* sub = ((GameObject*)obj)->extra;
    int control;

    if ((s8)((GroundBaddieState*)state)->baddie.moveJustStartedA != 0)
    {
        ObjAnim_SetCurrentMove(obj, 9, lbl_803E2D14, 0);
        ((GroundBaddieState*)state)->baddie.moveDone = 0;
    }
    control = *(int*)&sub->control;
    *(u8*)(control + 0x44) |= 0xc;
    if ((s8)((GroundBaddieState*)state)->baddie.moveJustStartedA != 0)
    {
        *(u8*)&((GameObject*)obj)->anim.resetHitboxMode |= 8;
        sub->targetState = 4;
    }
    *(s16*)obj = (s16)(lbl_803E2D5C *
        (((f32)((GroundBaddieState*)state)->baddie.turnRate * timeDelta) / lbl_803E2D60) +
        (f32) * (s16*)obj);
    ((GroundBaddieState*)state)->baddie.moveSpeed = lbl_803E2D38;
    ((GroundBaddieState*)state)->baddie.animSpeedA = lbl_803E2D48;
    return 0;
}

int mediumbasket_updateImpactHitState(int obj, int state)
{
    GroundBaddieState* sub = ((GameObject*)obj)->extra;
    int control = *(int*)&sub->control;

    ((ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState)->hitVolumePriority = 10;
    ((ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState)->hitVolumeId = 1;
    ObjHits_RegisterActiveHitVolumeObject(obj);
    if ((s8)((GroundBaddieState*)state)->baddie.moveJustStartedA != 0)
    {
        ((GroundBaddieState*)state)->baddie.moveDone = 0;
    }
    if ((s8)((GroundBaddieState*)state)->baddie.moveJustStartedA != 0)
    {
        ObjAnim_SetCurrentMove(obj, 4, lbl_803E2D14, 0);
        ((GroundBaddieState*)state)->baddie.moveDone = 0;
    }
    ((GroundBaddieState*)state)->baddie.unk34D = 3;
    ((GroundBaddieState*)state)->baddie.moveSpeed = lbl_803E2D28;
    if ((s32)(((GroundBaddieState*)state)->baddie.eventFlags & 0x200) != 0)
    {
        ((GroundBaddieState*)state)->baddie.eventFlags &= ~0x200;
        *(u8*)(control + 0x44) |= 0x10;
    }
    *(u8*)(control + 0x44) |= 0xc;
    return 0;
}

int mediumbasket_updateHideResetState(int obj, int state)
{
    extern undefined4 GameBit_Set(int eventId, int value); /* #57 */
    GroundBaddieState* sub = ((GameObject*)obj)->extra;
    ObjHitsPriorityState* hitState;

    if (((GroundBaddieState*)state)->baddie.unk276 != 4 && (s8)((GroundBaddieState*)state)->baddie.moveJustStartedA !=
        0)
    {
        ObjAnim_SetCurrentMove(obj, 0xe, lbl_803E2D14, 0);
        ((GroundBaddieState*)state)->baddie.moveDone = 0;
    }
    *(u8*)(*(int*)&sub->control + 0x44) |= 0xc;
    if ((s8)((GroundBaddieState*)state)->baddie.moveJustStartedA != 0)
    {
        hitState = (ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState;
        hitState->flags &= ~1;
        ((GroundBaddieState*)state)->baddie.moveSpeed = lbl_803E2D38;
        ((GroundBaddieState*)state)->baddie.animSpeedA = lbl_803E2D14;
    }
    if ((s8)((GroundBaddieState*)state)->baddie.moveDone != 0)
    {
        GameBit_Set((s32)sub->gameBitB, 0);
        ObjAnim_SetCurrentMove(obj, 8, lbl_803E2D14, 0);
        *(int*)&((GroundBaddieState*)state)->baddie.targetObj = 0;
        ((GroundBaddieState*)state)->baddie.physicsActive = 0;
        ((GroundBaddieState*)state)->baddie.hasTarget = 0;
        sub->targetState = 0;
        *(u8*)&((GameObject*)obj)->anim.resetHitboxMode |= 8;
    }
    return 0;
}

int mediumbasket_stateHandlerB06(int obj, int state)
{
    extern int* gPlayerInterface; /* #57 */
    extern int* gBaddieControlInterface; /* #57 */
    GroundBaddieState* sub = ((GameObject*)obj)->extra;
    int route;
    f32 neutralBlend;

    if ((s8)((GroundBaddieState*)state)->baddie.moveDone != 0 &&
        (((u8)((int (*)(int, int, f32))((void**)*gBaddieControlInterface)[6])(
            obj, state, lbl_803E2D00) & 1) == 0))
    {
        return 5;
    }
    if ((s8)((GroundBaddieState*)state)->baddie.moveJustStartedB != 0)
    {
        ((void (*)(int, int, int))((void**)*gPlayerInterface)[5])(obj, state, 0xb);
    }
    else if (sub->targetState == 3)
    {
        ((void (*)(int, int, int))((void**)*gPlayerInterface)[5])(obj, state, 4);
    }
    else if (sub->targetState == 4)
    {
        if (((GroundBaddieState*)state)->baddie.targetDistance < lbl_803E2D10 && (s8)((GroundBaddieState*)state)->baddie
            .moveDone != 0)
        {
            if (sub->aggression > 50)
            {
                ((void (*)(int, int, int))((void**)*gPlayerInterface)[5])(obj, state, 0);
            }
            else
            {
                ((void (*)(int, int, int))((void**)*gPlayerInterface)[5])(obj, state, 1);
            }
        }
    }
    else if (sub->targetState == 1)
    {
        return 8;
    }
    route = (int)sub->route35C;
    neutralBlend = lbl_803E2D14;
    ((GroundBaddieState*)state)->baddie.moveInputX = neutralBlend;
    ((GroundBaddieState*)state)->baddie.moveInputZ = neutralBlend;
    memcpy((void*)route, (void*)&((GameObject*)obj)->anim.localPosX, 0xc);
    memcpy((void*)(sub->route35C + 0xc), (void*)(*(int*)&((GroundBaddieState*)state)->baddie.targetObj + 0xc), 0xc);
    voxmaps_updateRoutePath((void*)route, (void*)(sub->route35C + 0x28));
    if (*(u8*)(route + 0x25) == 0)
    {
        ((void (*)(int, int, f32, f32, f32, f32, f32))((void**)*gPlayerInterface)[7])(
            obj, state, *(f32*)(route + 0x18), *(f32*)(route + 0x20), lbl_803E2D14,
            lbl_803E2D14, lbl_803E2D18);
    }
    else
    {
        ((void (*)(int, int, f32, f32, f32, f32, f32))((void**)*gPlayerInterface)[7])(
            obj, state, *(f32*)(route + 0x18), *(f32*)(route + 0x20), lbl_803E2D1C,
            lbl_803E2D20, lbl_803E2D18);
    }
    if (((GroundBaddieState*)state)->baddie.unk32E > 0x78 &&
        ((int (*)(int, int, f32, int))((void**)*gBaddieControlInterface)[17])(
            obj, state, (f32)sub->aggroRange, 1) != 0)
    {
        return 5;
    }
    return 0;
}

int mediumbasket_stateHandlerB07(int obj, int state)
{
    extern int* gPlayerInterface; /* #57 */
    extern int* gBaddieControlInterface; /* #57 */
    GroundBaddieState* sub = ((GameObject*)obj)->extra;

    if ((s8)((GroundBaddieState*)state)->baddie.moveJustStartedB != 0)
    {
        if ((s32)((GroundBaddieState*)state)->baddie.targetDistance > 0x37)
        {
            if ((sub->configFlags & 2) == 0)
            {
                ((void (*)(int, int, int))((void**)*gPlayerInterface)[5])(obj, state, 7);
            }
            else
            {
                int control = *(int*)&sub->control;
                if ((sub->configFlags & 0x10) != 0)
                {
                    int attackIndex = *(s16*)(control + 4);
                    *(u16*)(control + 4) = attackIndex + 1;
                    ((void (*)(int, int, int))((void**)*gPlayerInterface)[5])(
                        obj, state, (s32)lbl_8031FD90[attackIndex]);
                }
                else
                {
                    int attackIndex = *(s16*)(control + 4);
                    *(u16*)(control + 4) = attackIndex + 1;
                    ((void (*)(int, int, int))((void**)*gPlayerInterface)[5])(
                        obj, state, (s32)lbl_8031FD80[attackIndex]);
                }
                if (*(s16*)(control + 4) >= 7)
                {
                    *(s16*)(control + 4) = 0;
                }
            }
        }
        else
        {
            if (((GroundBaddieState*)state)->baddie.controlMode == 6)
            {
                ((void (*)(int, int, int))((void**)*gPlayerInterface)[5])(obj, state, 5);
            }
            else
            {
                ((void (*)(int, int, int))((void**)*gPlayerInterface)[5])(obj, state, 6);
            }
        }
    }
    else if ((s8)((GroundBaddieState*)state)->baddie.moveDone != 0)
    {
        if ((((u8)((int (*)(int, int, f32))((void**)*gBaddieControlInterface)[6])(
            obj, state, lbl_803E2D00) & 1) == 0))
        {
            return 5;
        }
        if (((int (*)(int, int, f32, int))((void**)*gBaddieControlInterface)[17])(
            obj, state, (f32)sub->aggroRange, 1) != 0)
        {
            return 5;
        }
        if ((s32)((GroundBaddieState*)state)->baddie.targetDistance > 0x37)
        {
            if ((sub->configFlags & 2) == 0)
            {
                ((void (*)(int, int, int))((void**)*gPlayerInterface)[5])(obj, state, 7);
            }
            else
            {
                int control = *(int*)&sub->control;
                if ((sub->configFlags & 0x10) != 0)
                {
                    int attackIndex = *(s16*)(control + 4);
                    *(u16*)(control + 4) = attackIndex + 1;
                    ((void (*)(int, int, int))((void**)*gPlayerInterface)[5])(
                        obj, state, (s32)lbl_8031FD90[attackIndex]);
                }
                else
                {
                    int attackIndex = *(s16*)(control + 4);
                    *(u16*)(control + 4) = attackIndex + 1;
                    ((void (*)(int, int, int))((void**)*gPlayerInterface)[5])(
                        obj, state, (s32)lbl_8031FD80[attackIndex]);
                }
                if (*(s16*)(control + 4) >= 7)
                {
                    *(s16*)(control + 4) = 0;
                }
            }
        }
        else
        {
            if (((GroundBaddieState*)state)->baddie.controlMode == 6)
            {
                ((void (*)(int, int, int))((void**)*gPlayerInterface)[5])(obj, state, 5);
            }
            else
            {
                ((void (*)(int, int, int))((void**)*gPlayerInterface)[5])(obj, state, 6);
            }
        }
    }
    else if (((GroundBaddieState*)state)->baddie.controlMode == 7 && (s32)((GroundBaddieState*)state)->baddie.
        targetDistance < 0x37)
    {
        if (((GroundBaddieState*)state)->baddie.controlMode == 6)
        {
            ((void (*)(int, int, int))((void**)*gPlayerInterface)[5])(obj, state, 5);
        }
        else
        {
            ((void (*)(int, int, int))((void**)*gPlayerInterface)[5])(obj, state, 6);
        }
    }
    return 0;
}

void fn_8015CE68(int obj, int state)
{
    int control = *(int*)(state + 0x40c);
    f32 transformedX;
    f32 transformedY;
    f32 transformedZ;
    u8 transformScratch[0x18];
    f32 pathX;
    f32 pathY;
    f32 pathZ;
    f32 pathMtx[16];
    f32 scale;
    f32 angle;

    memcpy(pathMtx, (void*)ObjPath_GetPointModelMtx(obj, 1), 0x40);
    pathMtx[14] = lbl_803E2D14;
    pathMtx[13] = lbl_803E2D14;
    pathMtx[12] = lbl_803E2D14;
    if (((GameObject*)obj)->anim.seqId == 99)
    {
        scale = lbl_803E2D48;
    }
    else
    {
        scale = lbl_803E2D2C;
    }
    if (((GroundBaddieState*)state)->baddie.animSpeedA >= scale)
    {
        scale = ((GroundBaddieState*)state)->baddie.animSpeedA;
    }
    if (((GroundBaddieState*)state)->baddie.controlMode == 4)
    {
        ObjPath_GetPointWorldPosition(obj, 0, (f32*)(control + 0x2c),
                                      (f32*)(control + 0x30), (f32*)(control + 0x34), 0);
    }
    else
    {
        ObjPath_GetPointWorldPosition(obj, 2, (f32*)(control + 0x2c),
                                      (f32*)(control + 0x30), (f32*)(control + 0x34), 0);
    }
    *(f32*)(control + 0x30) = lbl_803E2D90 + ((GameObject*)obj)->anim.localPosY;
    angle = (lbl_803E2D98 * (f32) * (s16*)obj) / lbl_803E2D9C;
    *(f32*)(control + 0x2c) =
        *(f32*)(control + 0x2c) - scale * (lbl_803E2D94 * mathSinf(angle));
    angle = (lbl_803E2D98 * (f32) * (s16*)obj) / lbl_803E2D9C;
    *(f32*)(control + 0x34) =
        *(f32*)(control + 0x34) - scale * (lbl_803E2D94 * mathCosf(angle));
    pathX = lbl_803E2D14;
    pathY = lbl_803E2DA0;
    pathZ = lbl_803E2DA4;
    ObjPath_GetPointWorldPosition(obj, 0, &pathX, &pathY, &pathZ, 1);
    if ((*(u8*)(control + 0x44) & 2) != 0)
    {
        transformedX = lbl_803E2DA8;
        transformedY = lbl_803E2DAC;
        transformedZ = lbl_803E2DA4;
        Matrix_TransformPoint(pathMtx, &transformedX, &transformedY, &transformedZ);
        memcpy((void*)(control + 0x38), &transformedX, 0xc);
        memcpy((void*)(control + 8), transformScratch, 0x18);
        *(u8*)(control + 0x44) |= 1;
    }
}

void mediumbasket_updateControlEffects(int obj, int state)
{
    int control = *(int*)(state + 0x40c);
    int paletteIndex;
    u8* particleArgs;
    int i;
    f32 shakeScale;
    f32 contactScale;

    if (((GameObject*)obj)->anim.seqId == 99)
    {
        *(f32*)(control + 0x28) = lbl_803E2D84;
        shakeScale = lbl_803E2D88;
    }
    else
    {
        contactScale = lbl_803E2D48;
        *(f32*)(control + 0x28) = contactScale;
        shakeScale = contactScale;
    }
    paletteIndex = 0;
    if ((s8)((GroundBaddieState*)state)->baddie.physicsActive != 0)
    {
        paletteIndex = lbl_8031FE48[(s8)((GroundBaddieState*)state)->baddie.paletteSlot];
        if (paletteIndex > 0x1e)
        {
            paletteIndex = 0;
        }
    }
    particleArgs = &lbl_8031FE38[paletteIndex * 3];
    if ((*(u8*)(control + 0x44) & 1) != 0)
    {
        mediumbasket_spawnContactObject((int*)obj, (int*)control);
        *(u8*)(control + 0x44) &= ~1;
    }
    if ((*(u8*)(control + 0x44) & 4) != 0 && (((GroundBaddieState*)state)->configFlags & 0x40) == 0)
    {
        for (i = 0; i < 4; i++)
        {
            (*gPartfxInterface)->spawnObject((void*)obj, 0x56, (void*)(control + 0x20), 0x200001, -1, particleArgs);
        }
    }
    if ((*(u8*)(control + 0x44) & 8) != 0 && (((GroundBaddieState*)state)->configFlags & 0x40) == 0)
    {
        (*gPartfxInterface)->spawnObject((void*)obj, 0x57, (void*)(control + 0x20), 0x200001, -1, particleArgs);
    }
    if ((*(u8*)(control + 0x44) & 0x10) != 0)
    {
        Camera_EnableViewYOffset();
        CameraShake_SetAllMagnitudes(lbl_803E2D88 * shakeScale);
        for (i = 0; i < 0x28; i++)
        {
            (*gPartfxInterface)->spawnObject((void*)obj, 0x57, (void*)(control + 0x20), 0x200001, -1, particleArgs);
        }
    }
    if ((*(u8*)(control + 0x44) & 0x20) != 0)
    {
        Camera_EnableViewYOffset();
        CameraShake_SetAllMagnitudes(lbl_803E2D8C * shakeScale);
        for (i = 0; i < 0x28; i++)
        {
            (*gPartfxInterface)->spawnObject((void*)obj, 0x57, (void*)(control + 0x20), 0x200001, -1, particleArgs);
        }
        for (i = 0; i < 10; i++)
        {
            (*gPartfxInterface)->spawnObject((void*)obj, 0x58, (void*)(control + 0x20), 0x200001, -1, particleArgs);
        }
    }
    *(u8*)(control + 0x44) = 0;
}

void mediumbasket_updateTargetMotion(int obj, int sub, int state)
{
    extern int* gPlayerInterface; /* #57 */
    extern int* gBaddieControlInterface; /* #57 */
    int control = *(int*)(sub + 0x40c);

    *(u16*)(control + 0x46) += framesThisStep;
    if (*(u16*)(control + 0x46) >= 300)
    {
        *(u16*)(control + 0x46) = randomGetRange(0, 200);
        if (((GroundBaddieState*)state)->baddie.controlMode == 7 || ((GroundBaddieState*)state)->baddie.controlMode ==
            8)
        {
            Sfx_PlayFromObject(obj, SFXkr_jump2);
        }
    }
    if ((*(u8*)(sub + 0x404) & 2) != 0)
    {
        ((void (*)(int, int, f32, int))((void**)*gBaddieControlInterface)[11])(
            obj, state, lbl_803E2D14, -1);
    }
    else
    {
        ((void (*)(int, int, f32, int))((void**)*gBaddieControlInterface)[11])(
            obj, state, lbl_803E2DB0, -1);
    }
    *(int*)(sub + 0x3e0) = *(int*)&((GameObject*)obj)->pendingParentObj;
    *(int*)&((GameObject*)obj)->pendingParentObj = 0;
    ((void (*)(int, int, f32, f32, u8*, u8*))((void**)*gPlayerInterface)[2])(
        obj, state, timeDelta, timeDelta, gMediumBasketStateHandlersA, gMediumBasketStateHandlersB);
    *(int*)&((GameObject*)obj)->pendingParentObj = *(int*)(sub + 0x3e0);
}

#pragma fp_contract off
void fn_8015D3C0(int obj, int sub, int state)
{
    extern int* gPlayerInterface; /* #57 */
    extern int* gBaddieControlInterface; /* #57 */
    int control = *(int*)(sub + 0x40c);
    u8* target;
    int hitInfo[7];
    f32 targetDelta[3];
    f32 distSq;

    Obj_GetPlayerObject();
    target = ((GroundBaddieState*)state)->baddie.targetObj;
    if (target != NULL)
    {
        targetDelta[0] = ((GameObject*)target)->anim.worldPosX - ((GameObject*)obj)->anim.worldPosX;
        targetDelta[1] = ((GameObject*)target)->anim.worldPosY - ((GameObject*)obj)->anim.worldPosY;
        targetDelta[2] = ((GameObject*)target)->anim.worldPosZ - ((GameObject*)obj)->anim.worldPosZ;
        distSq = targetDelta[2] * targetDelta[2];
        distSq += targetDelta[0] * targetDelta[0];
        distSq += targetDelta[1] * targetDelta[1];
        ((GroundBaddieState*)state)->baddie.targetDistance = sqrtf(distSq);
    }
    if ((((GroundBaddieState*)sub)->configFlags & 0x20) == 0)
    {
        ((void (*)(int, int, int, int, int, int, int))((void**)*gBaddieControlInterface)[15])(
            obj, state, sub + 0x400, 2, 3, (s32)((GroundBaddieState*)sub)->unk3FC,
            (s32)((GroundBaddieState*)sub)->unk3FA);
    }
    ((void (*)(int, int, int, int, int, int, int, int))((void**)*gBaddieControlInterface)[21])(
        obj, state, sub + 0x35c, (s32)((GroundBaddieState*)sub)->gameBitB, 0, 0, 0, 8);
    *(f32*)control += timeDelta;
    if (((GroundBaddieState*)state)->baddie.controlMode != 3 &&
        ((int (*)(int, int, int, int, u8*, u8*, int, int*))((void**)*gBaddieControlInterface)[20])(
            obj, state, sub + 0x35c, (s32)((GroundBaddieState*)sub)->gameBitB, lbl_8031FDA0,
            lbl_8031FE18, 1, hitInfo) != 0)
    {
        if (*(f32*)control < lbl_803E2DB4)
        {
            *(s16*)(control + 6) += 1;
        }
        else
        {
            *(s16*)(control + 6) = 0;
        }
        *(f32*)control = lbl_803E2D14;
        if ((s8)((GroundBaddieState*)state)->baddie.hitPoints > 0 && *(s16*)(control + 6) >= 2)
        {
            ((void (*)(int, int, int))((void**)*gPlayerInterface)[5])(obj, state, 3);
            *(s16*)(control + 6) = 0;
            ((GroundBaddieState*)state)->baddie.substate = 5;
        }
    }
}
#pragma fp_contract reset

s16 dll_CA_setScale(int* obj) { return *(s16*)((char*)((int**)obj)[0xb8 / 4] + 0x274); }

int dll_CA_getExtraSize_ret_1112(void) { return 0x458; }
int dll_CA_getObjectTypeId(void) { return 0x49; }

void dll_CA_free(int obj)
{
    extern int* gBaddieControlInterface; /* #57 */
    extern void Obj_FreeObject(int obj); /* #57 */
    GroundBaddieState* state = ((GameObject*)obj)->extra;

    Camera_DisableViewYOffset();
    ObjGroup_RemoveObject(obj, 3);
    if (((GameObject*)obj)->childObjs[0] != NULL)
    {
        Obj_FreeObject(*(int*)&((GameObject*)obj)->childObjs[0]);
        *(int*)&((GameObject*)obj)->childObjs[0] = 0;
    }
    ((void (*)(int, int, int))((void**)*gBaddieControlInterface)[16])(obj, (int)state, 0x20);
}

void dll_CA_render(int obj, int arg1, int arg2, int arg3, int arg4, s8 visible)
{
    extern void objRenderFn_8003b8f4(int obj, int arg1, int arg2, int arg3, int arg4, f32 scale); /* #57 */
    GroundBaddieState* state = ((GameObject*)obj)->extra;

    if (visible == 0)
    {
        goto done;
    }
    if (((GameObject*)obj)->unkF4 != 0)
    {
        goto done;
    }
    if (state->targetState != 0)
    {
        goto render;
    }
    goto done;

render:
    if (state->unk3E8 != lbl_803E2D14)
    {
        fn_8003B5E0(0xc8, 0, 0, (int)state->unk3E8);
    }
    objRenderFn_8003b8f4(obj, arg1, arg2, arg3, arg4, lbl_803E2D48);
    fn_8015CE68(obj, (int)state);
done:;
}

#pragma peephole on
void dll_CA_hitDetect(int obj)
{
    extern int* gPlayerInterface; /* #57 */
    ((void (*)(int, int, u8*))((void**)*gPlayerInterface)[3])(obj, *(int*)&((GameObject*)obj)->extra,
                                                              gMediumBasketStateHandlersA);
}

void mediumbasket_initWhirlpoolState(int* obj, GroundBaddieState* state)
{
    f32 fz;
    state->baddie.speedScale = lbl_803E2CE8;
    *(char*)&state->baddie.inWhirlpoolGroup = (int)state->baddie.unk2A8;
    state->baddie.unk2A8 = lbl_803E2CEC;
    state->baddie.unk2E4 = 0x42001;
    state->baddie.unk308 = lbl_803E2CF0;
    state->baddie.unk300 = lbl_803E2CF4;
    state->baddie.unk304 = lbl_803E2CF8;
    state->baddie.unk320 = 0;
    fz = lbl_803E2CFC;
    *(f32*)&state->baddie.eventFlags = fz;
    state->baddie.unk321 = 5;
    state->baddie.unk318 = fz;
    state->baddie.unk322 = 7;
    state->baddie.unk31C = fz;
    state->baddie.seqEntryIndex = 1;
    state->baddie.inWhirlpoolGroup = 0;
    ObjModel_SetRenderCallback(Obj_GetActiveModel(obj), (void*)renderWhirlpool);
}

#pragma peephole off
void mediumbasket_spawnContactObject(int* obj, int* state)
{
    void* alloc;
    int* new_obj;
    if ((u8)Obj_IsLoadingLocked() != 0)
    {
        alloc = Obj_AllocObjectSetup(36, 100);
        *(f32*)((char*)alloc + 8) = ((GroundBaddieState*)state)->baddie.posX;
        *(f32*)((char*)alloc + 12) = ((GroundBaddieState*)state)->baddie.posY;
        *(f32*)&((ObjDef*)alloc)->jointData = ((GroundBaddieState*)state)->baddie.posZ;
        *(u8*)((char*)alloc + 4) = 1;
        *(u8*)((char*)alloc + 5) = 1;
        *(u8*)((char*)alloc + 6) = 255;
        *(u8*)((char*)alloc + 7) = 255;
        *(s16*)((char*)alloc + 30) = -1;
        *(s16*)((char*)alloc + 32) = -1;
        new_obj = Obj_SetupObject(alloc, 5, -1, -1, (void*)0);
        if (new_obj != NULL)
        {
            ((GameObject*)new_obj)->anim.velocityX = ((GroundBaddieState*)state)->baddie.velX;
            ((GameObject*)new_obj)->anim.velocityY = ((GroundBaddieState*)state)->baddie.velY;
            ((GameObject*)new_obj)->anim.velocityZ = ((GroundBaddieState*)state)->baddie.velZ;
            *(int**)&((GameObject*)new_obj)->ownerObj = obj;
        }
    }
}

int mediumbasket_updateControlMove5State(int* obj, GroundBaddieState* state)
{
    extern int* gPlayerInterface; /* #57 */
    u8* t = *(u8**)((char*)(*(int**)&((GameObject*)obj)->extra) + 0x40c);
    t[0x44] |= 4;
    state->baddie.moveSpeed = lbl_803E2D38;
    if ((s8)state->baddie.moveJustStartedA != 0)
    {
        ObjAnim_SetCurrentMove((int)obj, 5, lbl_803E2D14, 0);
        state->baddie.moveDone = 0;
    }
    state->baddie.unk34D = 1;
    ((void(*)(int*, u8*, f32, int))((void**)*gPlayerInterface)[12])(obj, (u8*)state, timeDelta, 4);
    return 0;
}

int mediumbasket_stateHandlerB05(int* obj, GroundBaddieState* state)
{
    extern int* gPlayerInterface; /* #57 */
    if ((s8)state->baddie.moveJustStartedB != 0)
    {
        ((void(*)(int*, u8*, int))((void**)*gPlayerInterface)[5])(obj, (u8*)state, 3);
    }
    if ((s8)state->baddie.moveDone != 0)
    {
        if (state->baddie.controlMode == 3)
        {
            ((void(*)(int*, u8*, int))((void**)*gPlayerInterface)[5])(obj, (u8*)state, 0);
        }
        else
        {
            return 8;
        }
    }
    return 0;
}

int mediumbasket_stateHandlerB01(int* obj, GroundBaddieState* state)
{
    extern int* gPlayerInterface; /* #57 */
    GroundBaddieState* sub = ((GameObject*)obj)->extra;
    if ((s8)state->baddie.hitPoints < 1) return 3;
    if ((s8)state->baddie.moveDone != 0)
    {
        if (state->baddie.controlMode == 12)
        {
            if (sub->aggression > 50)
            {
                ((void(*)(int*, u8*, int))((void**)*gPlayerInterface)[5])(obj, (u8*)state, 0);
            }
            else
            {
                ((void(*)(int*, u8*, int))((void**)*gPlayerInterface)[5])(obj, (u8*)state, 1);
            }
        }
        else
        {
            return 8;
        }
    }
    return 0;
}

void mediumbasket_leaveWhirlpoolGroup(int obj, GroundBaddieState* state)
{
    if (state->baddie.inWhirlpoolGroup != 0)
    {
        ObjGroup_RemoveObject(obj, 80);
        state->baddie.inWhirlpoolGroup = 0;
    }
    *(u16*)obj = (float)(int)*(s16*)obj - lbl_803E2CD8 * timeDelta;
}

void mediumbasket_enterWhirlpoolGroup(int obj, GroundBaddieState* state)
{
    ObjHitsPriorityState* hitState;

    if (state->baddie.inWhirlpoolGroup == 0)
    {
        ObjGroup_AddObject(obj, 80);
        state->baddie.inWhirlpoolGroup = 1;
    }
    ObjHits_SetHitVolumeSlot(obj, 10, 1, 0);
    hitState = (ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState;
    hitState->suppressOutgoingHits = 0;
    ((GameObject*)obj)->anim.rotX -= 256;
}

void mediumbasket_tryAcquireTarget(int obj, int sub, int state)
{
    extern int* gBaddieControlInterface;
    extern int* gPlayerInterface;
    extern f32 timeDelta;
    extern f32 lbl_803E2D00;
    extern f32 lbl_803E2D24;
    extern f32 lbl_803E2D54;
    uint acquired;

    ObjHits_DisableObject(obj);

    if ((((GroundBaddieState*)sub)->configFlags & 0x4) != 0)
    {
        acquired = (**(uint (**)(int, int, f32, int))((char*)(*gBaddieControlInterface) + 0x48))(
            obj, state, lbl_803E2D54, 0x8000);
    }
    else if ((((GroundBaddieState*)sub)->configFlags & 0x8) != 0)
    {
        acquired = (**(uint (**)(int, int, f32, int))((char*)(*gBaddieControlInterface) + 0x48))(
            obj, state, lbl_803E2D24 * (f32)(u32)((GroundBaddieState*)sub)->aggroRange, 0x8000);
    }
    else
    {
        acquired = (**(uint (**)(int, int, f32, int))((char*)(*gBaddieControlInterface) + 0x48))(
            obj, state, (f32)(u32)((GroundBaddieState*)sub)->aggroRange, 0x8000);
    }

    if (acquired != 0)
    {
        (**(void (**)(int, int, f32, int))((char*)(*gPlayerInterface) + 0x30))(obj, state, timeDelta, 4);
        if (((u8)(**(int (**)(int, int, f32))((char*)(*gBaddieControlInterface) + 0x18))(obj, state, lbl_803E2D00) & 1) ==
            0)
        {
            acquired = 0;
        }
    }

    if (acquired != 0)
    {
        int v = -1;
        (**(void (**)(int, int, int, int, int, int, int, int, int))((char*)(*gBaddieControlInterface) + 0x28))(
            obj, state, sub + 0x35c, (s32)((GroundBaddieState*)sub)->gameBitB, 0, 0, 0, 8, v);
        *(int*)(state + 0x2d0) = acquired;
        *(u8*)(state + 0x349) = 0;
        ((GroundBaddieState*)sub)->targetState = 1;
    }
}

int mediumbasket_checkTargetState(int obj, int state)
{
    extern int* gPlayerInterface;
    extern int* gBaddieControlInterface;
    extern f32 timeDelta;
    extern f32 lbl_803E2D00;
    extern f32 lbl_803E2D14;
    extern f32 lbl_803E2D24;
    GroundBaddieState* sub = ((GameObject*)obj)->extra;
    f32 neutralBlend;

    if (((GroundBaddieState*)state)->baddie.targetObj == NULL) goto return0;

    if ((s32)(s8)((GroundBaddieState*)state)->baddie.moveJustStartedB != 0)
    {
        neutralBlend = lbl_803E2D14;
        ((GroundBaddieState*)state)->baddie.animSpeedB = neutralBlend;
        ((GroundBaddieState*)state)->baddie.animSpeedA = neutralBlend;
        if ((u32)sub->aggression > 50)
        {
            if (((GroundBaddieState*)state)->baddie.targetDistance < lbl_803E2D24 * (f32)(u32)
                sub->aggroRange
                    || (sub->configFlags & 0x2) != 0
            )
            {
                (**(void (**)(int, int, int))((char*)(*gPlayerInterface) + 0x14))(obj, state, 0);
            }
            else
            {
                (**(void (**)(int, int, int))((char*)(*gPlayerInterface) + 0x14))(obj, state, 1);
            }
        }
        else
        {
            (**(void (**)(int, int, int))((char*)(*gPlayerInterface) + 0x14))(obj, state, 1);
        }
    }

    if ((s32)(s8)((GroundBaddieState*)state)->baddie.moveDone == 0) goto return0;

    (**(void (**)(int, int, f32, int))((char*)(*gPlayerInterface) + 0x30))(obj, state, timeDelta, 4);
    if (((u8)(**(int (**)(int, int, f32))((char*)(*gBaddieControlInterface) + 0x18))(obj, state, lbl_803E2D00) & 1) == 0)
    {
        return 5;
    }

    if (((GroundBaddieState*)state)->baddie.targetDistance < lbl_803E2D24 * (f32)(u32)
        sub->aggroRange
            || (sub->configFlags & 0x2) != 0
    )
    {
        return 8;
    }
    return 7;

return0:
    return 0;
}

/* segment pragma-stack balance (re-split): */

void dll_CA_update(int obj, int p2, int p3)
{
    extern void Sfx_PlayFromObject(int obj, int sfx);
    extern int fn_8015D3C0(int obj, int sub, int sub2);
    extern void mediumbasket_updateControlEffects(int obj, int sub);
    extern void mediumbasket_tryAcquireTarget(int obj, int sub, int sub2);
    extern void mediumbasket_updateTargetMotion(int obj, int sub, int sub2);
    extern int* gBaddieControlInterface;
    extern MapEventInterface** gMapEventInterface;
    extern f32 lbl_803E2D14;
    extern f32 lbl_803E2D90;
    extern f32 lbl_803E2DB8;
    GroundBaddieState* sub;
    int setup;

    sub = ((GameObject*)obj)->extra;
    setup = *(int*)&((GameObject*)obj)->anim.placementData;
    if (((GameObject*)obj)->unkF4 != 0)
    {
        if ((sub->baddie.substate != 3 || (sub->configFlags & 1) != 0) &&
            (*gMapEventInterface)->shouldNotSaveTime(((ObjPlacement*)setup)->mapId) != 0)
        {
            (*(void (**)(int, int, int, int, int, int, int, f32))(*(int*)gBaddieControlInterface +
                0x58))(
                obj, setup, (int)sub, 14, 8, 0x102, 0x26, lbl_803E2DB8);
            sub->targetState = 0;
            Sfx_PlayFromObject(obj, SFXfoxcom_find);
            ObjAnim_SetCurrentMove((int)obj, 8, lbl_803E2D14, 0x10);
            *(s8*)&sub->baddie.moveDone = 0;
            ((GameObject*)obj)->anim.alpha = 0xff;
            *(u8*)&((GameObject*)obj)->anim.resetHitboxMode |= 8;
        }
    }
    else if (((GameObject*)obj)->unkF8 == 0)
    {
        ((GameObject*)obj)->anim.localPosX = ((ObjPlacement*)setup)->posX;
        ((GameObject*)obj)->anim.localPosY = ((ObjPlacement*)setup)->posY;
        ((GameObject*)obj)->anim.localPosZ = ((ObjPlacement*)setup)->posZ;
        (*gObjectTriggerInterface)->runSequence(*(s8*)(setup + 0x2e), (void*)obj, -1);
        ((GameObject*)obj)->unkF8 = 1;
    }
    else
    {
        if ((*(int (**)(int, int, int))(*(int*)gBaddieControlInterface + 0x30))(obj, (int)sub, 0) == 0)
        {
            sub->targetState = 0;
        }
        else
        {
            fn_8015D3C0(obj, (int)sub, (int)sub);
            mediumbasket_updateControlEffects(obj, (int)sub);
            if (sub->targetState == 0)
            {
                mediumbasket_tryAcquireTarget(obj, (int)sub, (int)sub);
            }
            else
            {
                mediumbasket_updateTargetMotion(obj, (int)sub, (int)sub);
            }
            if ((sub->configFlags & 2) != 0)
            {
                ((GameObject*)obj)->anim.localPosY = ((ObjPlacement*)setup)->posY - lbl_803E2D90;
            }
        }
    }
}

int fn_8015E3A0(int obj, int p2);

#pragma dont_inline on
void fn_8015DAE8(void);
#pragma dont_inline reset

void dll_CA_init(int obj, u8* params, int flags)
{
    extern int* gBaddieControlInterface;
    extern int* gPlayerInterface;
    extern f64 lbl_803E2D08;
    extern f32 lbl_803E2D14;
    extern f32 lbl_803E2D24;
    extern f32 lbl_803E2D54;
    extern f32 lbl_803E2DB8;
    GroundBaddieState* sub;
    u8 mode;

    sub = ((GameObject*)obj)->extra;
    mode = 6;
    if (flags != 0)
    {
        mode |= 1;
    }
    if ((*(u8*)(params + 0x2b) & 0x20) == 0)
    {
        mode |= 8;
    }
    (*(void (**)(int, u8*, int, int, int, int, u8, f32))(*(int*)gBaddieControlInterface + 0x58))(
        obj, params, (int)sub, 14, 8, 0x102, mode, lbl_803E2DB8);
    ((GameObject*)obj)->animEventCallback = NULL;
    if (lbl_803E2D24 * (f32)(u32)sub->aggroRange < lbl_803E2D54
    )
    {
        *(s16*)&sub->aggroRange = 0x6e;
    }
    ObjAnim_SetCurrentMove((int)obj, 8, lbl_803E2D14, 0);
    *(u8*)&((GameObject*)obj)->anim.resetHitboxMode |= 8;
    (*(void (**)(int, int, int))(*(int*)gPlayerInterface + 0x14))(obj, (int)sub, 0);
    sub->baddie.substate = 0;
    *(s8*)&sub->baddie.physicsActive = 0;
}

int fn_8015E5DC(short* obj, GroundBaddieState* p);

#pragma dont_inline on
#pragma dont_inline reset

static inline u8 scarab_isObjectInList(void* o);

#pragma dont_inline on
#pragma dont_inline reset

#pragma dont_inline on
#pragma dont_inline reset

#pragma scheduling on
#pragma peephole on
void dll_CA_release_nop(void)
{
}

void dll_CE_hitDetect_nop(void);

void chukchuk_free(void);

void chukchuk_hitDetect(void);

void chukchuk_release(void);

void chukchuk_initialise(void);

/*
 * Per-object extra state for the ChukChuk ice-spitter
 * (chukchuk_getExtraSize == 0x18).
 */

void chukchuk_init(u8* obj, u8* params);
void iceball_hitDetect(void);

void iceball_release(void);

void iceball_initialise(void);

int chukchuk_getExtraSize(void);
int chukchuk_getObjectTypeId(void);
int iceball_getExtraSize(void);
int iceball_getObjectTypeId(void);

void chukchuk_render(int p1, int p2, int p3, int p4, int p5, s8 visible);

void iceball_render(int p1, int p2, int p3, int p4, int p5, s8 visible);

void dll_CA_initialise(void) { fn_8015DAE8(); }
void iceball_free(void);

void chukchuk_update(short* obj);

void chukchuk_setScale(int obj, int v);

void iceball_init(void* obj);

ObjectDescriptor11WithPadding gChukChukObjDescriptor = {
    {
        0,
        0,
        0,
        OBJECT_DESCRIPTOR_FLAGS_11_SLOTS,
        (ObjectDescriptorCallback)chukchuk_initialise,
        (ObjectDescriptorCallback)chukchuk_release,
        0,
        (ObjectDescriptorCallback)chukchuk_init,
        (ObjectDescriptorCallback)chukchuk_update,
        (ObjectDescriptorCallback)chukchuk_hitDetect,
        (ObjectDescriptorCallback)chukchuk_render,
        (ObjectDescriptorCallback)chukchuk_free,
        (ObjectDescriptorCallback)chukchuk_getObjectTypeId,
        chukchuk_getExtraSize,
        (ObjectDescriptorCallback)chukchuk_setScale,
    },
    0,
};

ObjectDescriptor gIceBallObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)iceball_initialise,
    (ObjectDescriptorCallback)iceball_release,
    0,
    (ObjectDescriptorCallback)iceball_init,
    (ObjectDescriptorCallback)iceball_update,
    (ObjectDescriptorCallback)iceball_hitDetect,
    (ObjectDescriptorCallback)iceball_render,
    (ObjectDescriptorCallback)iceball_free,
    (ObjectDescriptorCallback)iceball_getObjectTypeId,
    iceball_getExtraSize,
};

/* scarab_updateProximityGate: scarab AI proximity gate. If no current target, dispatches
 * vtable[5](obj, state, 0) and returns 1. Else (unless state mode 6 means
 * already engaged) reads the angle from the obj to the target; when within
 * a +/-90? wedge the planar distance term is the constant lbl_803E2EB0,
 * otherwise it's sqrtf(dx*dx + dz*dz) - lbl_803E2EB4. The signed magnitude
 * drives three threshold checks against lbl_803E2EBC/EC0/EC4 that issue
 * vtable[5] calls with mode 6 (close), 1 (medium-out), or 1 (close-in)
 * depending on the current mode at (*(u8 *)&state->baddie.controlMode) and the latch byte at
 * state->baddie.moveDone. When mode == 1, picks one of two scalars (lbl_803E2EC8 or
 * lbl_803E2ECC) for (*(u8 *)&state->baddie.moveSpeed). Returns 0. */
