#include "main/dll/DIM/DIM2conveyor.h"
#include "main/game_object.h"
#include "main/objlib.h"
#include "main/objseq.h"

typedef struct DimbridgecogmaiObjectDef
{
    u8 pad0[0x18 - 0x0];
    s16 unk18;
    u8 pad1A[0x1C - 0x1A];
    u8 unk1C;
    u8 pad1D[0x20 - 0x1D];
} DimbridgecogmaiObjectDef;

typedef struct DimbridgecogmaiPlacement
{
    u8 pad0[0x18 - 0x0];
    s16 unk18;
    s16 unk1A;
    s16 unk1C;
    s16 unk1E;
} DimbridgecogmaiPlacement;

extern uint GameBit_Get(int eventId);
extern undefined4 GameBit_Set(int eventId, int value);

extern unsigned long GameBit_Set(int eventId, int value);
extern f32 lbl_803E4900;
extern void objRenderFn_8003b8f4(f32);

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

void dimbridgecogmai_free(int x) { ObjGroup_RemoveObject(x, 0xf); }

void dimbridgecogmai_release(void)
{
}

int dimdismountpoint_getObjectTypeId(void);

void dimbridgecogmai_init(int* obj, int* def)
{
    *(u8*)((GameObject*)obj)->extra = 100;
    *(s16*)obj = (s16)((u32)((DimbridgecogmaiObjectDef*)def)->unk1C << 8);
    ((GameObject*)obj)->animEventCallback = (void*)dimbridgecogmai_SeqFn;
    ObjGroup_AddObject((u32)obj, 15);
    if ((u8)GameBit_Get(((DimbridgecogmaiObjectDef*)def)->unk18) != 0)
    {
        ((GameObject*)obj)->objectFlags = (u16)(((GameObject*)obj)->objectFlags | 0x8000);
    }
    ((GameObject*)obj)->objectFlags = (u16)(((GameObject*)obj)->objectFlags | 0x6000);
}

int dimbridgecogmai_SeqFn(int obj, int unused, ObjAnimUpdateState* animUpdate)
{
    char* param = *(char**)&((GameObject*)obj)->anim.placementData;
    animUpdate->sequenceEventActive = 0;
    if ((*(u8*)(param + 0x1d) & 0x2) != 0 && animUpdate->triggerCommand == 1)
    {
        GameBit_Set(((DimbridgecogmaiPlacement*)param)->unk18, 1);
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
    if (GameBit_Get(((DimbridgecogmaiPlacement*)def)->unk1A) != 0)
    {
        if ((s8)def[0x1e] != -1)
        {
            switch (((DimbridgecogmaiPlacement*)def)->unk1A)
            {
            case 0x17a:
                if (GameBit_Get(0x181) != 0)
                {
                    ((GameObject*)obj)->objectFlags = (u16)(((GameObject*)obj)->objectFlags | 0x8000);
                    code = -1;
                    callArg = 0;
                }
                else
                {
                    GameBit_Set(((DimbridgecogmaiPlacement*)def)->unk1A, 0);
                    code = 0x1f;
                    callArg = 1;
                }
                break;
            case 0x1e3:
                bits = (u8)GameBit_Get(0x182);
                bits |= GameBit_Get(0x183) << 1;
                bits |= GameBit_Get(0x184) << 2;
                if (bits == 7)
                {
                    ((GameObject*)obj)->objectFlags = (u16)(((GameObject*)obj)->objectFlags | 0x8000);
                    code = -1;
                    callArg = 2;
                }
                else
                {
                    GameBit_Set(((DimbridgecogmaiPlacement*)def)->unk1A, 0);
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
            GameBit_Set(((DimbridgecogmaiPlacement*)def)->unk18, 1);
        }
    }
}

