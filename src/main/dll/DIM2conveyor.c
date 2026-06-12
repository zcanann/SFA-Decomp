#include "main/dll/DIM/DIM2conveyor.h"
#include "main/game_object.h"
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


typedef struct DimdismountpointState
{
    f32 unk0;
    f32 unk4;
    f32 unk8;
    f32 unkC;
} DimdismountpointState;


extern uint GameBit_Get(int eventId);
extern undefined4 GameBit_Set(int eventId, int value);
extern undefined8 ObjGroup_RemoveObject();
extern undefined4 ObjGroup_AddObject();

/*
 * --INFO--
 *
 * Function: dimlavasmash_init
 * EN v1.0 Address: 0x801B3658
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801B367C
 * EN v1.1 Size: 636b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */


/* Trivial 4b 0-arg blr leaves. */


void dimbridgecogmai_hitDetect(void)
{
}

void dimbridgecogmai_initialise(void)
{
}

void dimdismountpoint_hitDetect(void)
{
}

void dimdismountpoint_release(void)
{
}

void dimdismountpoint_initialise(void)
{
}

extern int* ObjGroup_FindNearestObject(int group, int* obj, f32* dist);
extern void objRenderFn_80041018(int obj);
extern f32 lbl_803E4910;

void dimdismountpoint_update(int* obj)
{
    extern uint GameBit_Get(int eventId);
    int* nearest;
    f32 d;

    d = lbl_803E4910;
    nearest = ObjGroup_FindNearestObject(0xa, obj, &d);
    *(u8*)&((GameObject*)obj)->anim.resetHitboxMode = (u8)(*(u8*)&((GameObject*)obj)->anim.resetHitboxMode & ~8);
    if (GameBit_Get(0x3e3) != 0)
    {
        ((GameObject*)obj)->unkE4 = 1;
        *(u8*)&((GameObject*)obj)->anim.resetHitboxMode = (u8)(*(u8*)&((GameObject*)obj)->anim.resetHitboxMode & ~0x10);
    }
    else
    {
        ((GameObject*)obj)->unkE4 = 0;
        if (nearest != NULL &&
            ((int (*)(int*, int*))(*(int*)(*(int*)*(int**)&((GameObject*)nearest)->anim.dll + 0x20)))(nearest, obj) !=
            0)
        {
            *(u8*)&((GameObject*)obj)->anim.resetHitboxMode = (u8)(
                *(u8*)&((GameObject*)obj)->anim.resetHitboxMode & ~0x10);
        }
        else
        {
            *(u8*)&((GameObject*)obj)->anim.resetHitboxMode = (u8)(
                *(u8*)&((GameObject*)obj)->anim.resetHitboxMode | 0x10);
        }
    }
    if ((((ObjAnimComponent*)obj)->modelInstance->flags & 1) != 0 && *(void**)((char*)obj + 0x74) != NULL)
    {
        objRenderFn_80041018((int)obj);
    }
}

extern f32 lbl_803E4908;
extern f32 lbl_803E4914;
extern f32 lbl_803E4918;
extern f32 mathSinf(f32 x);
extern f32 mathCosf(f32 x);
extern unsigned long GameBit_Set(int eventId, int value);

void dimdismountpoint_init(u8* obj, u8* params)
{
    f32* sub;

    ObjGroup_AddObject(obj, 0x13);
    *(s16*)obj = (s16)((s8)params[0x18] << 8);
    sub = ((GameObject*)obj)->extra;
    sub[0] = mathSinf(lbl_803E4914 * (f32)(s32) * (s16*)obj / lbl_803E4918);
    sub[1] = lbl_803E4908;
    sub[2] = mathCosf(lbl_803E4914 * (f32)(s32) * (s16*)obj / lbl_803E4918);
    sub[3] = -(sub[0] * ((GameObject*)obj)->anim.localPosX + sub[1] * ((GameObject*)obj)->anim.localPosY + sub[2] * ((
        GameObject*)obj)->anim.localPosZ);
    ((GameObject*)obj)->unkF8 = 1;
}

/* 8b "li r3, N; blr" returners. */
int dimbridgecogmai_getExtraSize(void) { return 0x1; }
int dimbridgecogmai_getObjectTypeId(void) { return 0x0; }
int dimdismountpoint_getExtraSize(void) { return 0x10; }

/* render-with-objRenderFn_8003b8f4 pattern. */
extern f32 lbl_803E4900;
extern void objRenderFn_8003b8f4(f32);

void dimbridgecogmai_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0) objRenderFn_8003b8f4(lbl_803E4900);
}

/* ObjGroup_RemoveObject(x, N) wrappers. */
void dimbridgecogmai_free(int x) { ObjGroup_RemoveObject(x, 0xf); }
void dimdismountpoint_free(int x) { ObjGroup_RemoveObject(x, 0x13); }

void dimbridgecogmai_release(void)
{
}

int dimdismountpoint_getObjectTypeId(void) { return 0; }

void dimbridgecogmai_init(int* obj, int* def)
{
    *(u8*)((GameObject*)obj)->extra = 100;
    *(s16*)obj = (s16)((u32)((DimbridgecogmaiObjectDef*)def)->unk1C << 8);
    ((GameObject*)obj)->animEventCallback = (void*)dimbridgecogmai_SeqFn;
    ObjGroup_AddObject(obj, 15);
    if ((u8)GameBit_Get(((DimbridgecogmaiObjectDef*)def)->unk18) != 0)
    {
        ((GameObject*)obj)->objectFlags = (u16)(((GameObject*)obj)->objectFlags | 0x8000);
    }
    ((GameObject*)obj)->objectFlags = (u16)(((GameObject*)obj)->objectFlags | 0x6000);
}

extern f32 lbl_803E490C;

void dimdismountpoint_render(int obj, int p1, int p2, int p3, int p4, s8 visible)
{
    if (visible == 0 || ((GameObject*)obj)->unkF8 != 0)
    {
        if (((GameObject*)obj)->unkF8 != 0)
        {
            objRenderFn_80041018(obj);
        }
    }
    else
    {
        objRenderFn_8003b8f4(lbl_803E490C);
    }
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

extern ObjectTriggerInterface** gObjectTriggerInterface;

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

void dimdismountpoint_func11(int obj, int flag)
{
    (*gObjectTriggerInterface)->runSequence((flag ^ 1) + 2, (void*)obj, -1);
}

extern int Obj_GetPlayerObject(void);

int dimdismountpoint_setScale(int obj)
{
    int* player = (int*)Obj_GetPlayerObject();
    int* state = ((GameObject*)obj)->extra;
    f32 result;
    int side;

    result = ((DimdismountpointState*)state)->unkC +
    (((DimdismountpointState*)state)->unk8 * ((GameObject*)player)->anim.localPosZ +
        (((DimdismountpointState*)state)->unk0 * ((GameObject*)player)->anim.localPosX +
            ((DimdismountpointState*)state)->unk4 * ((GameObject*)player)->anim.localPosY));

    if (result >= lbl_803E4908)
    {
        side = 0;
    }
    else
    {
        side = 1;
    }
    (*gObjectTriggerInterface)->runSequence(side, (void*)obj, -1);
    return side;
}
