#include "main/game_object.h"
#include "main/audio/sfx.h"
#include "main/dll_000A_expgfx.h"
#include "main/gamebits.h"
#include "main/main.h"
#include "main/objtexture.h"
#include "main/objlib.h"
#include "main/resource.h"

extern u32 randomGetRange(int min, int max);
extern undefined4 FUN_80017ac8();

extern ModgfxInterface** gModgfxInterface;
extern undefined4 DAT_803de944;
extern undefined4 DAT_803de946;
extern f32 lbl_803DC074;

extern void fn_801FD6B4(int obj);
extern void* lbl_803DDCD8;
extern void objRenderFn_80041018(void* obj);
extern void fn_8003B608(int r, int g, int b);
extern f32 lbl_803E6168;
extern void objRenderFn_8003b8f4(f32);
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
extern void* getTrickyObject(void);
extern f32 mathSinf(f32 x);

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

typedef struct
{
    s16 showGameBit; /* 0x0 */
    s16 checkGameBit; /* 0x2 */
    s8 counter; /* 0x4 */
    u8 done : 1; /* 0x5 bit 7 */
    u8 noCheck : 1; /* 0x5 bit 6 */
    u8 pad06[2];
} VfpFlamePointData;

typedef struct VfpLavaStarState
{
    f32 verticalVelocity;
    f32 delayRangeMin;
    f32 delayRangeMax;
    s16 gameBit;
    s16 effectTimer;
    u8 particleToggle;
    u8 pad11[3];
} VfpLavaStarState;

typedef struct VfpLavaStarMapData
{
    ObjPlacement base;
    u8 pad18[2];
    s16 heightOffset;
    u8 pad1C[2];
    s16 gameBit;
} VfpLavaStarMapData;

STATIC_ASSERT(sizeof(VfpFlamePointData) == 0x08);
STATIC_ASSERT(offsetof(VfpFlamePointData, showGameBit) == 0x00);
STATIC_ASSERT(offsetof(VfpFlamePointData, checkGameBit) == 0x02);
STATIC_ASSERT(offsetof(VfpFlamePointData, counter) == 0x04);
STATIC_ASSERT(sizeof(VfpLavaStarState) == 0x14);
STATIC_ASSERT(offsetof(VfpLavaStarState, verticalVelocity) == 0x00);
STATIC_ASSERT(offsetof(VfpLavaStarState, delayRangeMin) == 0x04);
STATIC_ASSERT(offsetof(VfpLavaStarState, delayRangeMax) == 0x08);
STATIC_ASSERT(offsetof(VfpLavaStarState, gameBit) == 0x0C);
STATIC_ASSERT(offsetof(VfpLavaStarState, effectTimer) == 0x0E);
STATIC_ASSERT(offsetof(VfpLavaStarState, particleToggle) == 0x10);
STATIC_ASSERT(offsetof(VfpLavaStarMapData, heightOffset) == 0x1A);
STATIC_ASSERT(offsetof(VfpLavaStarMapData, gameBit) == 0x1E);

int vfpflamepoint_getExtraSize(void) { return sizeof(VfpFlamePointData); }
int return1_801FDA08(void) { return 0x1; }
int VFP_lavapool_getExtraSize_ret_24(void) { return 0x18; }
int VFP_lavapool_getObjectTypeId(void) { return 0x0; }
int vfplavastar_getExtraSize(void) { return sizeof(VfpLavaStarState); }
int vfplavastar_getObjectTypeId(void) { return 0x0; }
int vfpspellplace_getExtraSize(void) { return sizeof(LaserState); }
int vfpspellplace_getObjectTypeId(void) { return 0x0; }
int dbegg_getExtraSize(void);

void VFP_lavapool_update(int obj) { fn_801FD6B4(obj); }

#pragma scheduling off
void vfplavastar_release(void)
{
    Resource_Release(lbl_803DDCD8);
    lbl_803DDCD8 = NULL;
}

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

int dbegg_setScale(int obj);

void vfplavastar_initialise(void)
{
    lbl_803DDCD8 = NULL;
    lbl_803DDCD8 = Resource_Acquire(0xa6, 1);
}

void vfplavastar_free(int obj)
{
    (*gExpgfxInterface)->freeSource2((u32)obj);
    (*gModgfxInterface)->freeSourceEffects((void*)obj);
}

#pragma peephole off
void VFP_lavapool_render(int obj, int p1, int p2, int p3, int p4, s8 visible)
{
    if (visible != 0)
    {
        fn_8003B608(0xff, 0xe6, 0xd7);
        ((void (*)(int, int, int, int, int, f32))objRenderFn_8003b8f4)(obj, p1, p2, p3, p4, lbl_803E6168);
    }
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
                if (d->noCheck || (void*)ObjGroup_FindNearestObject(5, obj, &dist) == NULL)
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

#pragma peephole on
void fn_801FD6B4(int obj)
{
    u8* extra;
    int def;
    f32 speed;
    f32 c;
    ObjTextureRuntimeSlot* tex;
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
        Sfx_PlayFromObject((u32)obj, 0x111);
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
    tex = objFindTexture((void*)obj, 0, 0);
    if (tex != NULL)
    {
        v = (f32)(int)tex->offsetT + lbl_803E6160;
        if (v >= lbl_803E6194)
        {
            v -= lbl_803E6194;
        }
        tex->offsetT = (s16)(int)v;
    }
    tex = objFindTexture((void*)obj, 1, 0);
    if (tex != NULL)
    {
        v = (f32)(int)tex->offsetT + lbl_803E6198;
        if (v >= lbl_803E6194)
        {
            v -= lbl_803E6194;
        }
        tex->offsetT = (s16)(int)v;
    }
}

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

void vfplavastar_update(int obj)
{
    VfpLavaStarMapData* mapData;
    VfpLavaStarState* state;

    mapData = (VfpLavaStarMapData*)*(int*)&((GameObject*)obj)->anim.placementData;
    state = ((GameObject*)obj)->extra;
    ((GameObject*)obj)->anim.localPosY += timeDelta * state->verticalVelocity;
    if (((GameObject*)obj)->anim.localPosY > lbl_803E61B0 + mapData->base.posY)
    {
        state->verticalVelocity = lbl_803E61B4 * (f32)(int)
        randomGetRange(5, 0x14);
        ((GameObject*)obj)->anim.localPosY = mapData->base.posY;
    }
    state->effectTimer += (s16)timeDelta;
    if (lbl_803DDCD8 != 0 && state->effectTimer >= 0x28)
    {
        (*(void (*)(int, int, int, int, int, int))*(int*)(*(int*)lbl_803DDCD8 + 4))(obj, 0, 0, 4, -1, 0);
        state->effectTimer = 0;
    }
    if (state->particleToggle == 0)
    {
        (*gPartfxInterface)->spawnObject((void*)obj, 0x3a4, NULL, 2, -1, NULL);
    }
    state->particleToggle ^= 1;
}

void vfplavastar_init(int obj, int def)
{
    VfpLavaStarState* state;
    VfpLavaStarMapData* mapData;

    mapData = (VfpLavaStarMapData*)def;
    state = ((GameObject*)obj)->extra;
    state->gameBit = mapData->gameBit;
    state->verticalVelocity = lbl_803E61B4 * (f32)(int)
    randomGetRange(10, 0x19);
    state->effectTimer = 0x14;
    ((GameObject*)obj)->anim.localPosY = mapData->base.posY + (f32)(int)mapData->heightOffset;
    ((GameObject*)obj)->objectFlags |= 0x2000;
    state->delayRangeMin = (f32)(int)
    randomGetRange(0x1e, 0x3c);
    state->delayRangeMax = (f32)(int)
    randomGetRange(100, 200);
}

void vfpspellplace_update(int obj)
{
    LaserObject* spellPlace;
    LaserState* state;
    u8 mode;

    spellPlace = (LaserObject*)obj;
    if (spellPlace->state->completionLatched == 0 && GameBit_Get((int)spellPlace->state->activationGameBit) != 0)
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
        mode = (*gMapEventInterface)->getMapAct((int)spellPlace->mapEventSlot);
        switch (mode)
        {
        case LASEROBJ_MODE_SEQUENCE_A:
            state = spellPlace->state;
            if ((*gGameUIInterface)->isEventReady(LASEROBJ_MAIN_SEQUENCE_A_EVENT) != 0)
            {
                GameBit_Set(state->completionGameBit, 1);
                GameBit_Set(state->activationGameBit, 0);
                state->completionLatched = 1;
                spellPlace->statusFlags |= LASER_OBJECT_STATUS_DISABLED;
            }
            break;
        case LASEROBJ_MODE_SEQUENCE_B:
            state = spellPlace->state;
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
