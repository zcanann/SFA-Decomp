#include "main/game_object.h"
#include "main/obj_placement.h"
#include "main/audio/sfx_ids.h"
#include "main/dll/anim_internal.h"
#include "main/effect_interfaces.h"
#include "main/expgfx.h"
#include "main/main.h"
#include "main/objlib.h"
#include "main/resource.h"

extern uint GameBit_Get(int eventId);
extern void GameBit_Set(int eventId, int value);
extern u32 randomGetRange(int min, int max);
extern undefined4 FUN_80017ac8();

extern ModgfxInterface** gModgfxInterface;
extern EffectInterface** gPartfxInterface;
extern MapEventInterface** gMapEventInterface;
extern undefined4 DAT_803de944;
extern undefined4 DAT_803de946;
extern f32 lbl_803DC074;

/*
 * --INFO--
 *
 * Function: FUN_801fd398
 * EN v1.0 Address: 0x801FD398
 * EN v1.0 Size: 852b
 * EN v1.1 Address: 0x801FD3A4
 * EN v1.1 Size: 720b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801fd398(undefined8 param_1, undefined8 param_2, undefined8 param_3, undefined8 param_4,
                  undefined8 param_5, undefined8 param_6, undefined8 param_7, undefined8 param_8,
                  int param_9)
{
    char cVar1;
    uint uVar2;
    int iVar3;
    short* psVar4;
    double dVar5;

    cVar1 = *(char*)(*(int*)&((GameObject*)param_9)->anim.placementData + 0x19);
    if (cVar1 == '\x02')
    {
        iVar3 = *(int*)&((GameObject*)param_9)->extra;
        DAT_803de944 = DAT_803de944 - (short)(int)lbl_803DC074;
        uVar2 = GameBit_Get((int)*(short*)(iVar3 + 2));
        if (((uVar2 == 0) && (DAT_803de944 < 0xc9)) &&
            ((*(char*)(iVar3 + 0xb) == DAT_803de946 && (uVar2 = randomGetRange(0, 2), uVar2 == 0))))
        {
            (*gPartfxInterface)->spawnObject((void*)param_9, 0x391, NULL, 4, -1, NULL);
        }
    }
    else if (((GameObject*)param_9)->anim.seqId == 0x3c5)
    {
        iVar3 = *(int*)&((GameObject*)param_9)->extra;
        *(short*)(iVar3 + 6) = *(short*)(iVar3 + 6) - (short)(int)lbl_803DC074;
        ((GameObject*)param_9)->anim.localPosX =
            ((GameObject*)param_9)->anim.velocityX * lbl_803DC074 + ((GameObject*)param_9)->anim.localPosX;
        ((GameObject*)param_9)->anim.localPosY =
            ((GameObject*)param_9)->anim.velocityY * lbl_803DC074 + ((GameObject*)param_9)->anim.localPosY;
        dVar5 = (double)lbl_803DC074;
        ((GameObject*)param_9)->anim.localPosZ =
            (float)((double)((GameObject*)param_9)->anim.velocityZ * dVar5 + (double)((GameObject*)param_9)->anim.
                localPosZ);
        if (*(short*)(iVar3 + 6) < 1)
        {
            FUN_80017ac8(dVar5, (double)((GameObject*)param_9)->anim.velocityZ, param_3, param_4, param_5, param_6,
                         param_7,
                         param_8, param_9);
        }
    }
    else if (cVar1 == '\0')
    {
        iVar3 = *(int*)&((GameObject*)param_9)->extra;
        DAT_803de944 = DAT_803de944 - (short)(int)lbl_803DC074;
        uVar2 = GameBit_Get(0x522);
        if ((((uVar2 == 0) && (DAT_803de944 < 0xc9)) && (*(char*)(iVar3 + 0xb) == DAT_803de946)) &&
            (uVar2 = randomGetRange(0, 2), uVar2 == 0))
        {
            (*gPartfxInterface)->spawnObject((void*)param_9, 0x391, NULL, 4, -1, NULL);
        }
    }
    else if (cVar1 == '\x01')
    {
        psVar4 = ((GameObject*)param_9)->extra;
        uVar2 = GameBit_Get((int)*psVar4);
        if (uVar2 != 0)
        {
            (*gPartfxInterface)->spawnObject((void*)param_9, 0x390, NULL, 4, -1, NULL);
            (*gPartfxInterface)->spawnObject((void*)param_9, 0x390, NULL, 4, -1, NULL);
            uVar2 = randomGetRange(0, 1);
            if (uVar2 != 0)
            {
                (*gPartfxInterface)->spawnObject((void*)param_9, 0x391, NULL, 4, -1, NULL);
            }
        }
        iVar3 = ObjHits_GetPriorityHit(param_9, (int*)0x0, (int*)0x0, (uint*)0x0);
        if ((short)iVar3 != 0)
        {
            uVar2 = GameBit_Get((int)*psVar4);
            GameBit_Set((int)*psVar4, 1 - uVar2);
        }
    }
    return;
}


#pragma scheduling off
#pragma peephole off
void dbegg_processMessages(int obj)
{
    extern int gameBitIncrement(int);
    extern void Obj_RemoveFromUpdateList(int);
    extern void vecRotateZXY(void*, int);
    extern f32 lbl_803E61C8;
    extern f32 lbl_803E61CC;

    AnimBehaviorConfig* config;
    int sub;
    u32 msgType = 0;
    int msgFlag = 0;
    int msgArg;

    sub = *(int*)&((GameObject*)obj)->extra;
    config = (AnimBehaviorConfig*)((GameObject*)obj)->anim.placementData;

    while (ObjMsg_Pop((void*)obj, &msgType, (uint*)&msgArg, (uint*)&msgFlag) != 0)
    {
        if (msgType == 17)
        {
            switch (msgFlag)
            {
            case 18:
                if ((*(u8*)(sub + 0x119) & 0x20) == 0)
                {
                    ObjGroup_RemoveObject(obj, 36);
                }
                ObjHits_DisableObject(obj);
                *(u8*)(sub + 0x118) = 11;
                *(u8*)&((GameObject*)obj)->anim.resetHitboxMode = (u8)(
                    *(u8*)&((GameObject*)obj)->anim.resetHitboxMode | 0x8);
                break;
            case 17:
                {
                    f32 buf[6];
                    s16* hbuf = (s16*)buf;
                    f32 v;
                    ((GameObject*)obj)->anim.velocityX = *(f32*)(sub + 0x10c);
                    ((GameObject*)obj)->anim.velocityY = *(f32*)(sub + 0x110);
                    ((GameObject*)obj)->anim.velocityZ = -*(f32*)(sub + 0x114);
                    v = lbl_803E61C8;
                    buf[3] = v;
                    buf[4] = v;
                    buf[5] = v;
                    buf[2] = lbl_803E61CC;
                    hbuf[2] = 0;
                    hbuf[1] = 0;
                    hbuf[0] = *(s16*)msgArg;
                    vecRotateZXY(buf, obj + 0x24);
                }
            /* fallthrough */
            case 16:
                ObjGroup_AddObject(obj, 36);
            /* fallthrough */
            case 20:
                *(u8*)(sub + 0x118) = 5;
                *(u8*)&((GameObject*)obj)->anim.resetHitboxMode = (u8)(
                    *(u8*)&((GameObject*)obj)->anim.resetHitboxMode & ~0x8);
                ObjHits_EnableObject(obj);
                break;
            case 19:
                GameBit_Set(config->secondaryConditionId, 1);
                if (config->activationEventId > 0)
                {
                    gameBitIncrement(config->activationEventId);
                }
                Obj_RemoveFromUpdateList(obj);
                ((GameObject*)obj)->anim.flags = (s16)(((GameObject*)obj)->anim.flags | OBJANIM_FLAG_HIDDEN);
                ObjGroup_RemoveObject(obj, 36);
                break;
            }
        }
    }
}
#pragma peephole reset
#pragma scheduling reset


/* Trivial 4b 0-arg blr leaves. */
void dll_224_release_nop(void)
{
}

void dll_224_initialise_nop(void)
{
}

void VFP_lavapool_free_nop(void)
{
}

void VFP_lavapool_hitDetect_nop(void)
{
}

void VFP_lavapool_release_nop(void)
{
}

void VFP_lavapool_initialise_nop(void)
{
}

void vfplavastar_render(void)
{
}

void vfplavastar_hitDetect(void)
{
}

void vfpspellplace_free(void)
{
}

void vfpspellplace_render(void)
{
}

void vfpspellplace_hitDetect(void)
{
}

void vfpspellplace_release(void)
{
}

void vfpspellplace_initialise(void)
{
}

/* 8b "li r3, N; blr" returners. */
int vfpflamepoint_getExtraSize(void) { return 0x8; }
int return1_801FDA08(void) { return 0x1; }
int VFP_lavapool_getExtraSize_ret_24(void) { return 0x18; }
int VFP_lavapool_getObjectTypeId(void) { return 0x0; }
int vfplavastar_getExtraSize(void) { return 0x14; }
int vfplavastar_getObjectTypeId(void) { return 0x0; }
int vfpspellplace_getExtraSize(void) { return 0x6; }
int vfpspellplace_getObjectTypeId(void) { return 0x0; }
int dbegg_getExtraSize(void) { return 0x124; }
int dbegg_getObjectTypeId(void) { return 0x8; }

/* ObjGroup_RemoveObject(x, N) wrappers. */
#pragma scheduling off
void dbegg_free(int x) { ObjGroup_RemoveObject(x, 0x24); }
#pragma scheduling reset

/* plain forwarder. */
extern void fn_801FD6B4(int obj);
void VFP_lavapool_update(int obj) { fn_801FD6B4(obj); }

/* fn_X(lbl); lbl = 0; */
extern void* lbl_803DDCD8;
#pragma scheduling off
void vfplavastar_release(void)
{
    Resource_Release(lbl_803DDCD8);
    lbl_803DDCD8 = NULL;
}
#pragma scheduling reset

/* dll_224_hitDetect: render iff obj->field_0x74 set. */
extern void objRenderFn_80041018(void* obj);

void dll_224_hitDetect(void* obj)
{
    if (*(void**)((char*)obj + 0x74) != NULL)
    {
        objRenderFn_80041018(obj);
    }
}

/* dll_224_update: dispatch GameEvent id based on vtable[0x40](obj->field_0xac). */
extern int lbl_803DDCC8;
extern void spellStoneUseFn_801fd270(void* obj);
#pragma scheduling off
#pragma peephole off
void dll_224_update(void* param_1)
{
    void* obj = param_1;
    int v;
    v = (*gMapEventInterface)->getMode(((GameObject*)obj)->anim.mapEventSlot);
    v = (u8)v;
    switch (v)
    {
    case 1:
        lbl_803DDCC8 = 0x123;
        break;
    case 2:
        lbl_803DDCC8 = 0x83b;
        break;
    case 3:
        lbl_803DDCC8 = 0x83c;
        break;
    default:
        lbl_803DDCC8 = 0x123;
        break;
    }
    spellStoneUseFn_801fd270(obj);
}
#pragma peephole reset
#pragma scheduling reset

typedef struct
{
    s16 showGameBit; /* 0x0 */
    s16 checkGameBit; /* 0x2 */
    s8 counter; /* 0x4 */
    u8 done : 1; /* 0x5 bit 7 */
    u8 noCheck : 1; /* 0x5 bit 6 */
} VfpFlamePointData;

/* fn_801FD4A8: decrement extra->[4] by x; return whether it reached 0. */
#pragma scheduling off
int fn_801FD4A8(void* obj, int x)
{
    u8* extra = ((GameObject*)obj)->extra;
    if (extra != NULL)
    {
        s8 v = extra[4] - x;
        extra[4] = v;
        return *(s8*)(extra + 4) <= 0 ? 1 : 0;
    }
    return 0;
}
#pragma scheduling reset

int dbegg_setScale(int obj)
{
    u8* inner = ((GameObject*)obj)->extra;
    return inner[0x118] != 3 ? 1 : 0;
}

/* dbegg_setupFromDef: set up dbegg from def fields, dispatch on def->_26 mode byte. */
extern f32 lbl_803E61C8;
extern f32 lbl_803E61D0;
extern int fn_801FE560(int obj, f32* out, f32 a, f32 b, int p3);
extern int Obj_SetActiveModelIndex(int obj, int idx);
#pragma scheduling off
#pragma peephole off
void dbegg_setupFromDef(int obj, u8* state)
{
    AnimBehaviorConfig* config;
    f32 local_unused;

    config = (AnimBehaviorConfig*)((GameObject*)obj)->anim.placementData;
    state[0x119] = 0;
    *(s16*)obj = (s16)(config->facingAngleByte << 8);
    ((GameObject*)obj)->anim.rotY = 0;
    ((GameObject*)obj)->anim.rotZ = 0;
    ((GameObject*)obj)->anim.rootMotionScale = (f32)(u32)
    config->speedScaleByte * lbl_803E61D0;
    ((GameObject*)obj)->anim.rootMotionScale = ((GameObject*)obj)->anim.rootMotionScale * *(f32*)(*(int*)&((GameObject*)
        obj)->anim.modelInstance + 4);
    state[0x118] = (u8)(GameBit_Get(config->primaryConditionId) != 0 ? 3 : 1);
    if (state[0x118] == 1)
    {
        if (fn_801FE560(obj, &local_unused, lbl_803E61C8, *(f32*)&lbl_803E61C8, 1) == 0)
        {
            state[0x118] = 2;
        }
    }
    if (config->behaviorMode != 0)
    {
        state[0x119] |= 1;
        if (config->behaviorMode == 2) state[0x119] |= 2;
        if (config->behaviorMode == 3) state[0x118] = 10;
        if (config->behaviorMode == 4)
        {
            state[0x119] |= 4;
            state[0x119] = (u8)(state[0x119] & ~1);
        }
        if (config->behaviorMode == 5)
        {
            state[0x119] |= 8;
            state[0x119] |= 16;
        }
        if (config->behaviorMode == 6)
        {
            Obj_SetActiveModelIndex(obj, 1);
            state[0x119] |= 8;
            state[0x119] |= 16;
        }
        if (config->behaviorMode == 7) state[0x119] |= 32;
    }
    state[0x118] = (u8)(GameBit_Get(config->readyConditionId) != 0 ? 5 : 12);
    if (state[0x118] == 5)
    {
        ObjGroup_AddObject(obj, 36);
    }
    {
        f32 fz = lbl_803E61C8;
        ((GameObject*)obj)->anim.velocityX = fz;
        ((GameObject*)obj)->anim.velocityY = fz;
        ((GameObject*)obj)->anim.velocityZ = fz;
        ((GameObject*)obj)->unkF8 = 0;
        *(f32*)state = fz;
    }
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
int dbegg_func0B(int obj, f32* v)
{
    char* inner = ((GameObject*)obj)->extra;
    if (*(u8*)(inner + 0x118) == 0xb)
    {
        *(f32*)(inner + 0x10c) = v[0];
        *(f32*)(inner + 0x110) = v[1];
        *(f32*)(inner + 0x114) = v[2];
        return 1;
    }
    return 0;
}
#pragma scheduling reset

#pragma scheduling off
void vfplavastar_initialise(void)
{
    lbl_803DDCD8 = NULL;
    lbl_803DDCD8 = Resource_Acquire(0xa6, 1);
}
#pragma scheduling reset

#pragma scheduling off
void vfplavastar_free(int obj)
{
    (*gExpgfxInterface)->freeSource2((u32)obj);
    (*gModgfxInterface)->freeSourceEffects((void*)obj);
}
#pragma scheduling reset

extern void fn_8003B608(int r, int g, int b);
extern f32 lbl_803E6168;
extern void objRenderFn_8003b8f4(f32);
#pragma scheduling off
#pragma peephole off
void VFP_lavapool_render(int obj, int p1, int p2, int p3, int p4, s8 visible)
{
    if (visible != 0)
    {
        fn_8003B608(0xff, 0xe6, 0xd7);
        ((void (*)(int, int, int, int, int, f32))objRenderFn_8003b8f4)(obj, p1, p2, p3, p4, lbl_803E6168);
    }
}
#pragma peephole reset
#pragma scheduling reset

extern f32 lbl_803E61CC;
#pragma scheduling off
#pragma peephole off
void dbegg_render(int obj, int p1, int p2, int p3, int p4, s8 visible)
{
    u8* inner = ((GameObject*)obj)->extra;
    if (visible != 0)
    {
        u32 t = inner[0x118];
        if (t != 0xc && t != 4 && t != 0xb)
        {
            ((void(*)(int, int, int, int, int, f32))objRenderFn_8003b8f4)(obj, p1, p2, p3, p4, lbl_803E61CC);
        }
    }
}
#pragma peephole reset
#pragma scheduling reset

/* dll_224_init: init extra-data fields from other; set obj->0xaf bit 3. */
#pragma scheduling off
#pragma peephole off
void dll_224_init(void* obj, void* other)
{
    s16* extra = ((GameObject*)obj)->extra;
    s16 v = (s16)((s8) * ((s8*)other + 0x18) << 8);
    u8 t;
    *(s16*)obj = v;
    *(s16*)((char*)extra + 0) = *(s16*)((char*)other + 0x1e);
    *(s16*)((char*)extra + 2) = *(s16*)((char*)other + 0x20);
    t = (u8)(*(u8*)&((GameObject*)obj)->anim.resetHitboxMode | 0x8);
    *(u8*)&((GameObject*)obj)->anim.resetHitboxMode = t;
}

void vfpflamepoint_init(int* obj, s8* def)
{
    VfpFlamePointData* d = (VfpFlamePointData*)obj[0xb8 / 4];
    d->counter = (s8) * (s16*)(def + 0x1a);
    d->noCheck = (u8) * (s16*)(def + 0x1c);
    d->showGameBit = *(s16*)(def + 0x1e);
    d->checkGameBit = *(s16*)(def + 0x20);
    ((GameObject*)obj)->objectFlags |= 0x6000;
}
#pragma peephole reset
#pragma scheduling reset

extern int objBboxFn_800640cc(void* from, void* to, f32 radius, int mode, void* hit, int obj, int p7, int p8, int p9,
                              int p10);
extern f32 lbl_803E6218;
extern f32 lbl_803E621C;

#pragma scheduling off
void dbegg_hitDetect(int obj)
{
    u8* state;
    int hit;
    hit = ObjHits_GetPriorityHit(obj, 0, 0, 0);
    state = ((GameObject*)obj)->extra;
    if (hit == 0x12)
    {
        if (state[0x118] != 4)
        {
            Obj_GetPlayerObject();
        }
    }
    if (state[0x118] != 9)
    {
        void* hitFrom = (void*)&((GameObject*)obj)->anim.previousLocalPosX;
        void* hitTo = (void*)&((GameObject*)obj)->anim.localPosX;
        f32 hitRadius = lbl_803E6218;
        if (objBboxFn_800640cc(hitFrom, hitTo, hitRadius, 1, NULL, obj, 8, -1, 0xff, 0) != 0)
        {
            f32 damping = lbl_803E621C;
            f32 velocityX = ((GameObject*)obj)->anim.velocityX;
            ((GameObject*)obj)->anim.velocityX = velocityX - damping * velocityX;
            velocityX = ((GameObject*)obj)->anim.velocityZ;
            ((GameObject*)obj)->anim.velocityZ = velocityX - damping * velocityX;
        }
    }
    ((GameObject*)obj)->anim.previousLocalPosX = ((GameObject*)obj)->anim.localPosX;
    ((GameObject*)obj)->anim.previousLocalPosY = ((GameObject*)obj)->anim.localPosY;
    ((GameObject*)obj)->anim.previousLocalPosZ = ((GameObject*)obj)->anim.localPosZ;
}
#pragma scheduling reset

/* ==== v1.0 recovered functions (drift additions) ==== */

extern f32 timeDelta;
extern f32 lbl_803DDCD0;
extern f32 lbl_803E6158;
extern f32 lbl_803E6160;
extern f32 lbl_803E6164;
extern f32 lbl_803E616C;
extern f32 lbl_803E6170;
extern f32 lbl_803E6174;
extern f32 lbl_803E6178;
extern f32 lbl_803E617C;
extern f32 lbl_803E6180;
extern f32 lbl_803E6184;
extern f32 lbl_803E6188;
extern f32 lbl_803E618C;
extern f32 lbl_803E6190;
extern f32 lbl_803E6194;
extern f32 lbl_803E6198;
extern f32 lbl_803E61B0;
extern f32 lbl_803E61B4;
extern f32 lbl_803E61E0;
extern f32 lbl_803E61E4;
extern f32 lbl_803E61E8;
extern f32 lbl_803E61EC;
extern f32 lbl_803E61F0;
extern f32 lbl_803E61F4;
extern f32 lbl_803E61F8;
extern f32 lbl_803E61FC;
extern f32 lbl_803E6200;
extern f32 lbl_803E6204;
extern f32 lbl_803E6208;
extern void* getTrickyObject(void);
extern void Sfx_PlayFromObject(int obj, int sfxId);
extern int* objFindTexture(int obj, int idx, int p3);
extern f32 mathSinf(f32 x);
extern f32 mathCosf(f32 x);
extern f32 sqrtf(f32 x);
extern int hitDetectFn_80065e50(f32 x, f32 y, f32 z, int obj, int*** listOut, int p6, int p7);

#pragma scheduling off
#pragma peephole off
void vfpflamepoint_update(int obj)
{
    VfpFlamePointData* d;
    void* tricky;

    d = ((GameObject*)obj)->extra;
    *(u8*)&((GameObject*)obj)->anim.resetHitboxMode |= 8;
    if (!d->done && (d->checkGameBit == -1 || GameBit_Get(d->checkGameBit) != 0))
    {
        if (d->counter <= 0 && !d->done)
        {
            if (d->showGameBit != -1)
            {
                GameBit_Set(d->showGameBit, 1);
                d->done = 1;
            }
        }
        else
        {
            tricky = getTrickyObject();
            if (tricky != NULL)
            {
                f32 dist = lbl_803E6158;
                if (d->noCheck || ObjGroup_FindNearestObject(5, obj, &dist) == 0)
                {
                    if (*(u8*)&((GameObject*)obj)->anim.resetHitboxMode & 4)
                    {
                        (*(void (*)(void*, int, int, int))*(int*)(*(int*)*(int*)((u8*)tricky + 0x68) + 0x28))(
                            tricky, obj, 1, 4);
                    }
                    *(u8*)&((GameObject*)obj)->anim.resetHitboxMode &= ~8;
                    objRenderFn_80041018((void*)obj);
                }
            }
        }
    }
    else
    {
        u8 v = (u8)GameBit_Get(d->showGameBit);
        d->done = v;
        if (!d->done)
        {
            d->counter = (s8) * (s16*)(*(int*)&((GameObject*)obj)->anim.placementData + 0x1a);
        }
    }
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
void fn_801FD6B4(int obj)
{
    u8* extra;
    int def;
    f32 speed;
    f32 c;
    int* tex;
    f32 v;
    struct
    {
        u8 pad[8];
        f32 value;
        f32 unused[2];
    } parm;

    extra = ((GameObject*)obj)->extra;
    def = *(int*)&((GameObject*)obj)->anim.placementData;
    speed = (f32)(u32)((GameObject*)obj)->anim.alpha;
    *(f32*)(extra + 0xc) += timeDelta * ((lbl_803E6160 * *(f32*)(extra + 0x10)) / lbl_803E6160);
    if (*(f32*)(extra + 0xc) > lbl_803E6164)
    {
        *(f32*)(extra + 0x10) = (f32)(int)
        randomGetRange(0x32, 100);
        *(f32*)(extra + 8) = lbl_803E6168 / ((f32)(int) * (s16*)(def + 0x1a) / (f32)(int)
        randomGetRange(0x15e, 800)
        )
        ;
        *(f32*)(extra + 0xc) = lbl_803E616C;
        Sfx_PlayFromObject(obj, 0x111);
        speed = lbl_803E6170;
    }
    lbl_803DDCD0 = mathSinf((lbl_803E6174 * (f32)(s16)(int) * (f32*)(extra + 0xc)) / lbl_803E6178);
    ((GameObject*)obj)->anim.rootMotionScale = lbl_803E617C * *(f32*)(extra + 8) + lbl_803E6180 * *(f32*)(extra + 8) *
        lbl_803DDCD0;
    c = *(f32*)(extra + 0xc);
    if (c > lbl_803E6184 && c < lbl_803E6188)
    {
        parm.value = *(f32*)(extra + 8);
        if (((GameObject*)obj)->objectFlags & 0x800)
        {
            (*gPartfxInterface)->spawnObject((void*)obj, 0x3a2, &parm, 2, -1, NULL);
        }
    }
    c = *(f32*)(extra + 0xc);
    if (c > lbl_803E618C)
    {
        speed = (f32)(s16)(int)(lbl_803E6170 * lbl_803DDCD0);
    }
    if (c < lbl_803E6190)
    {
        speed = lbl_803E6170 * (c / lbl_803E6190);
    }
    *(s8*)&((GameObject*)obj)->anim.alpha = (int)((speed < lbl_803E616C)
                                                      ? lbl_803E616C
                                                      : ((speed > lbl_803E6170) ? lbl_803E6170 : speed));
    tex = objFindTexture(obj, 0, 0);
    if (tex != NULL)
    {
        v = (f32)(int) * (s16*)((u8*)tex + 0xa) + lbl_803E6160;
        if (v >= lbl_803E6194)
        {
            v -= lbl_803E6194;
        }
        *(s16*)((u8*)tex + 0xa) = (s16)(int)
        v;
    }
    tex = objFindTexture(obj, 1, 0);
    if (tex != NULL)
    {
        v = (f32)(int) * (s16*)((u8*)tex + 0xa) + lbl_803E6198;
        if (v >= lbl_803E6194)
        {
            v -= lbl_803E6194;
        }
        *(s16*)((u8*)tex + 0xa) = (s16)(int)
        v;
    }
}
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void VFP_lavapool_init(int obj, int def)
{
    int extra;

    extra = *(int*)&((GameObject*)obj)->extra;
    ((GameObject*)obj)->animEventCallback = (void*)return1_801FDA08;
    *(s16*)(extra + 4) = 7000;
    *(s16*)(extra + 6) = 2000;
    if (*(s16*)(def + 0x1a) == 0)
    {
        *(s16*)(def + 0x1a) = 500;
    }
    ((GameObject*)obj)->anim.rootMotionScale = lbl_803E6168 / ((f32)(int) * (s16*)(def + 0x1a) / (f32)(int)
    randomGetRange(600, 1000)
    )
    ;
    *(f32*)(extra + 8) = ((GameObject*)obj)->anim.rootMotionScale;
    *(f32*)(extra + 0x10) = (f32)(int)
    randomGetRange(0x32, 100);
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void vfplavastar_update(int obj)
{
    int def;
    f32* extra;

    def = *(int*)&((GameObject*)obj)->anim.placementData;
    extra = ((GameObject*)obj)->extra;
    ((GameObject*)obj)->anim.localPosY += timeDelta * extra[0];
    if (((GameObject*)obj)->anim.localPosY > lbl_803E61B0 + ((ObjPlacement*)def)->posY)
    {
        extra[0] = lbl_803E61B4 * (f32)(int)
        randomGetRange(5, 0x14);
        ((GameObject*)obj)->anim.localPosY = ((ObjPlacement*)def)->posY;
    }
    *(s16*)((u8*)extra + 0xe) += (s16)(int)
    timeDelta;
    if (lbl_803DDCD8 != 0 && *(s16*)((u8*)extra + 0xe) > 0x27)
    {
        (*(void (*)(int, int, int, int, int, int))*(int*)(*(int*)lbl_803DDCD8 + 4))(obj, 0, 0, 4, -1, 0);
        *(s16*)((u8*)extra + 0xe) = 0;
    }
    if (*(u8*)(extra + 4) == 0)
    {
        (*gPartfxInterface)->spawnObject((void*)obj, 0x3a4, NULL, 2, -1, NULL);
    }
    *(u8*)(extra + 4) ^= 1;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void vfplavastar_init(int obj, int def)
{
    f32* extra;

    extra = ((GameObject*)obj)->extra;
    *(s16*)((u8*)extra + 0xc) = *(s16*)(def + 0x1e);
    extra[0] = lbl_803E61B4 * (f32)(int)
    randomGetRange(10, 0x19);
    *(s16*)((u8*)extra + 0xe) = 0x14;
    ((GameObject*)obj)->anim.localPosY = ((ObjPlacement*)def)->posY + (f32)(int) * (s16*)(def + 0x1a);
    ((GameObject*)obj)->objectFlags |= 0x2000;
    extra[1] = (f32)(int)
    randomGetRange(0x1e, 0x3c);
    extra[2] = (f32)(int)
    randomGetRange(100, 200);
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void vfpspellplace_update(int obj)
{
    LaserObject* spellPlace;
    LaserState* state;
    u8 mode;

    spellPlace = (LaserObject*)obj;
    state = spellPlace->state;
    if (state->completionLatched == 0 && GameBit_Get((int)state->activationGameBit) != 0)
    {
        spellPlace->statusFlags &= ~LASER_OBJECT_STATUS_DISABLED;
    }
    else
    {
        spellPlace->statusFlags |= LASER_OBJECT_STATUS_DISABLED;
    }
    objRenderFn_80041018((void*)obj);
    if (spellPlace->statusFlags & LASER_OBJECT_STATUS_ACTIVE)
    {
        mode = (*gMapEventInterface)->getMode((int)spellPlace->mapEventSlot);
        switch (mode)
        {
        case LASEROBJ_MODE_SEQUENCE_A:
            if ((*gGameUIInterface)->isEventReady(LASEROBJ_MAIN_SEQUENCE_A_EVENT) != 0)
            {
                GameBit_Set(state->completionGameBit, 1);
                GameBit_Set(state->activationGameBit, 0);
                state->completionLatched = 1;
                spellPlace->statusFlags |= LASER_OBJECT_STATUS_DISABLED;
            }
            break;
        case LASEROBJ_MODE_SEQUENCE_B:
            if ((*gGameUIInterface)->isEventReady(LASEROBJ_MAIN_SEQUENCE_B_EVENT) != 0)
            {
                GameBit_Set(state->completionGameBit, 1);
                GameBit_Set(state->activationGameBit, 0);
                state->completionLatched = 1;
                spellPlace->statusFlags |= LASER_OBJECT_STATUS_DISABLED;
            }
            break;
        }
    }
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void vfpspellplace_init(int obj, s8* def)
{
    LaserObject* spellPlace;
    LaserObjectMapData* mapData;
    LaserState* state;

    spellPlace = (LaserObject*)obj;
    mapData = (LaserObjectMapData*)def;
    state = spellPlace->state;
    state->completionGameBit = mapData->completionGameBit;
    state->activationGameBit = mapData->activationGameBit;
    state->completionLatched = 0;
    spellPlace->modeWord = (s16)(mapData->mapEventSlot << LASEROBJ_MODE_WORD_SHIFT);
    if (GameBit_Get(state->completionGameBit) != 0)
    {
        state->completionLatched = 1;
        spellPlace->statusFlags |= LASER_OBJECT_STATUS_DISABLED;
    }
    spellPlace->objectFlags |= LASER_OBJECT_FLAGS_SEQUENCE_CONTROL;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
#pragma opt_common_subs off
#pragma opt_loop_invariants off
int fn_801FE560(int obj, f32* out, f32 a, f32 b, int flag)
{
    f32 water;
    f32 ground;
    f32 t;
    f32 u;
    f32 dy;
    int n;
    int i;
    int** list;
    int** cursor;
    int* hit;

    *out = lbl_803E61C8;
    n = hitDetectFn_80065e50(((GameObject*)obj)->anim.localPosX + a, ((GameObject*)obj)->anim.localPosY,
                             ((GameObject*)obj)->anim.localPosZ + b, obj, &list, 0, 0);
    if (n != 0)
    {
        ground = lbl_803E61E0;
        water = ground;
        cursor = list;
        for (i = 0; i < n; i++)
        {
            hit = *cursor;
            dy = *(f32*)hit - ((GameObject*)obj)->anim.localPosY;
            if (*(s8*)((u8*)hit + 0x14) == 0xe)
            {
                if (water >= lbl_803E61C8)
                {
                    t = water;
                }
                else
                {
                    t = -water;
                }
                if (dy >= lbl_803E61C8)
                {
                    u = dy;
                }
                else
                {
                    u = -dy;
                }
                if (u < t)
                {
                    water = dy;
                }
            }
            else
            {
                if (ground >= lbl_803E61C8)
                {
                    t = ground;
                }
                else
                {
                    t = -ground;
                }
                if (dy >= lbl_803E61C8)
                {
                    u = dy;
                }
                else
                {
                    u = -dy;
                }
                if (u < t)
                {
                    ground = dy;
                }
            }
            cursor++;
        }
        if (flag == 0)
        {
            if (lbl_803E61E0 != ground)
            {
                *out = ground;
                return 0;
            }
            if (lbl_803E61E0 != water)
            {
                *out = water;
                return 1;
            }
            *out = lbl_803E61E4;
        }
        else
        {
            if (lbl_803E61E0 != water)
            {
                if (ground >= lbl_803E61C8)
                {
                    t = ground;
                }
                else
                {
                    t = -ground;
                }
                if (water >= lbl_803E61C8)
                {
                    u = water;
                }
                else
                {
                    u = -water;
                }
                if (u <= t || water > lbl_803E61C8)
                {
                    *out = water;
                    return 0;
                }
                *out = ground;
                return 1;
            }
            if (lbl_803E61E0 != ground)
            {
                *out = ground;
                return 1;
            }
            *out = lbl_803E61E4;
        }
    }
    return 0;
}
#pragma opt_loop_invariants reset
#pragma opt_common_subs reset
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
void fn_801FE774(int cam, f32* vel)
{
    f32 limit;
    f32 force;
    f32 sumX;
    f32 sumZ;
    int count;
    int* objs;
    u8* o;
    int i;

    sumZ = sumX = lbl_803E61C8;
    objs = (int*)ObjGroup_GetObjects(0x14, &count);
    limit = lbl_803E61E8;
    for (i = 0; i < count; i++)
    {
        f32 dy;
        o = (u8*)*objs;
        dy = *(f32*)(o + 0x10) - *(f32*)(cam + 0x10);
        if (dy <= limit && dy >= lbl_803E61EC)
        {
            f32 dx = *(f32*)(o + 0xc) - *(f32*)(cam + 0xc);
            f32 dz = *(f32*)(o + 0x14) - *(f32*)(cam + 0x14);
            f32 dist = sqrtf(dx * dx + dz * dz);
            f32 radius = lbl_803E61F0 * (f32)(u32) * (u8*)(*(int*)(o + 0x4c) + 0x19);
            if (dist < radius)
            {
                force = (radius - dist) / radius;
                force = force * (lbl_803E61F4 * *(f32*)(o + 8));
                sumX += force * mathSinf((lbl_803E61F8 * (f32)(int) * (s16*)o) / lbl_803E61FC);
                sumZ += force * mathCosf((lbl_803E61F8 * (f32)(int) * (s16*)o) / lbl_803E61FC);
            }
        }
        objs++;
    }
    if (count != 0)
    {
        f32 w;
        f32 m;
        sumX = sumX / (f32)count;
        sumZ = sumZ / (f32)count;
        vel[0] = -(sumX * (w = lbl_803E6200) - vel[0]);
        vel[2] = -(w * sumZ - vel[2]);
        vel[0] = vel[0] * (m = lbl_803E6204);
        vel[2] = vel[2] * m;
        {
            f32 mag = sqrtf(vel[0] * vel[0] + vel[2] * vel[2]);
            if (mag > lbl_803E6208)
            {
                f32 sc = lbl_803E6208 / mag;
                vel[0] = vel[0] * sc;
                vel[2] = vel[2] * sc;
            }
        }
    }
}
#pragma scheduling reset
