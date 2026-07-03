/*
 * dimbridgecogmai (DLL 0x1C8) — bridge cog main object for Dinosaur Island
 * Mission 2.  Watches one or more gamebits and, when they become set, either
 * hides the cog or triggers an animation sequence depending on the gamebit
 * value; also fires sequence events from the SeqFn callback.
 */
#include "main/dll/DIM/DIM2conveyor.h"
#include "main/game_object.h"
#include "main/objlib.h"
#include "main/objseq.h"
#include "main/gamebits.h"
#include "main/dll/VF/vf_shared.h"

/* Cog-puzzle gamebits for DIM2 bridge puzzle */
#define COGBIT_PANEL_A     0x17a
#define COGBIT_PANEL_B     0x181
#define COGBIT_BRIDGE      0x1e3
#define COGBIT_SLOT_0      0x182
#define COGBIT_SLOT_1      0x183
#define COGBIT_SLOT_2      0x184

#define DIMBRIDGECOG_GROUP 0xf

#define DIMBRIDGECOGMAI_OBJFLAG_HIDDEN 0x4000
#define DIMBRIDGECOGMAI_OBJFLAG_HITDETECT_DISABLED 0x2000
#define DIMBRIDGECOGMAI_OBJFLAG_UPDATE_DISABLED 0x8000

typedef struct DimbridgecogmaiObjectDef
{
    u8 pad0[0x18 - 0x0];
    s16 watchGameBit;
    u8 pad1A[0x1C - 0x1A];
    u8 rotationAngle;
    u8 pad1D[0x20 - 0x1D];
} DimbridgecogmaiObjectDef;

typedef struct DimbridgecogmaiPlacement
{
    u8 pad0[0x18 - 0x0];
    s16 doneGameBit;
    s16 watchGameBit;
    s16 groupId;
    s16 unk1E;
} DimbridgecogmaiPlacement;

extern f32 lbl_803E4900;

void dimbridgecogmai_hitDetect(void)
{
}

void dimbridgecogmai_initialise(void)
{
}

int dimbridgecogmai_getExtraSize(void) { return 0x1; }
int dimbridgecogmai_getObjectTypeId(void) { return 0x0; }

void dimbridgecogmai_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0) objRenderFn_8003b8f4(lbl_803E4900);
}

void dimbridgecogmai_free(int x) { ObjGroup_RemoveObject(x, DIMBRIDGECOG_GROUP); }

void dimbridgecogmai_release(void)
{
}


void dimbridgecogmai_init(int* obj, int* def)
{
    *(u8*)((GameObject*)obj)->extra = 100;
    ((GameObject*)obj)->anim.rotX = (s16)((u32)((DimbridgecogmaiObjectDef*)def)->rotationAngle << 8);
    ((GameObject*)obj)->animEventCallback = dimbridgecogmai_SeqFn;
    ObjGroup_AddObject((u32)obj, DIMBRIDGECOG_GROUP);
    if ((u8)GameBit_Get(((DimbridgecogmaiObjectDef*)def)->watchGameBit) != 0)
    {
        ((GameObject*)obj)->objectFlags = (u16)(((GameObject*)obj)->objectFlags | DIMBRIDGECOGMAI_OBJFLAG_UPDATE_DISABLED);
    }
    ((GameObject*)obj)->objectFlags = (u16)(((GameObject*)obj)->objectFlags | (DIMBRIDGECOGMAI_OBJFLAG_HIDDEN | DIMBRIDGECOGMAI_OBJFLAG_HITDETECT_DISABLED));
}

int dimbridgecogmai_SeqFn(int obj, int unused, ObjAnimUpdateState* animUpdate)
{
    char* param = *(char**)&((GameObject*)obj)->anim.placementData;
    animUpdate->sequenceEventActive = 0;
    if ((*(u8*)(param + 0x1d) & 0x2) != 0 && animUpdate->triggerCommand == 1)
    {
        GameBit_Set(((DimbridgecogmaiPlacement*)param)->doneGameBit, 1);
        animUpdate->triggerCommand = 0;
    }
    return 0;
}

void dimbridgecogmai_update(int* obj)
{
    u8* def;
    int code;
    u8 bits;
    int callArg;

    def = *(u8**)&((GameObject*)obj)->anim.placementData;
    if (GameBit_Get(((DimbridgecogmaiPlacement*)def)->watchGameBit) != 0)
    {
        if ((s8)def[0x1e] != -1)
        {
            switch (((DimbridgecogmaiPlacement*)def)->watchGameBit)
            {
            case COGBIT_PANEL_A:
                if (GameBit_Get(COGBIT_PANEL_B) != 0)
                {
                    ((GameObject*)obj)->objectFlags = (u16)(((GameObject*)obj)->objectFlags | DIMBRIDGECOGMAI_OBJFLAG_UPDATE_DISABLED);
                    code = -1;
                    callArg = 0;
                }
                else
                {
                    GameBit_Set(((DimbridgecogmaiPlacement*)def)->watchGameBit, 0);
                    code = 0x1f;
                    callArg = 1;
                }
                break;
            case COGBIT_BRIDGE:
                bits = GameBit_Get(COGBIT_SLOT_0);
                bits |= GameBit_Get(COGBIT_SLOT_1) << 1;
                bits |= GameBit_Get(COGBIT_SLOT_2) << 2;
                if (bits == 7)
                {
                    ((GameObject*)obj)->objectFlags = (u16)(((GameObject*)obj)->objectFlags | DIMBRIDGECOGMAI_OBJFLAG_UPDATE_DISABLED);
                    code = -1;
                    callArg = 2;
                }
                else
                {
                    GameBit_Set(((DimbridgecogmaiPlacement*)def)->watchGameBit, 0);
                    code = 0x1d;
                    if ((bits & 4) != 0)
                    {
                        code = code | 2;
                        if ((bits & 2) != 0)
                        {
                            code = code | 0x20;
                        }
                    }
                    callArg = 1;
                }
                break;
            default:
                callArg = 0;
                break;
            }
            (*gObjectTriggerInterface)->runSequence(callArg, obj, code);
        }
        if ((def[0x1d] & 2) == 0)
        {
            GameBit_Set(((DimbridgecogmaiPlacement*)def)->doneGameBit, 1);
        }
    }
}
