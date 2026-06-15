/* DLL 0x01FC (laserbeam) — WC laser beam and related objects [0x801F0AE4-0x801F160C). */
#include "main/dll/dll1fbstate_struct.h"
#include "main/dll/laserbeamstate_struct.h"
#include "main/dll/dll200state_struct.h"
#include "main/effect_interfaces.h"
#include "main/obj_placement.h"
#include "main/objlib.h"

extern int Obj_GetPlayerObject(void);
extern void textureFree(void* resource);

extern ModgfxInterface** gModgfxInterface;

extern f32 timeDelta;

#define OBJ_PTR(obj, offset) (*(void **)((u8 *)(obj) + (offset)))

typedef struct Dll1FBSetup
{
    ObjPlacement base;
    s8 yawByte;
    s8 baseMove;
    s16 triggerMode;
    s16 objectParam;
} Dll1FBSetup;

typedef struct WMGalleonSetup
{
    ObjPlacement base;
    s8 yawByte;
} WMGalleonSetup;

typedef struct WMSeqObjectSetup
{
    ObjPlacement base;
    s8 yawByte;
    s8 setupType;
} WMSeqObjectSetup;

typedef struct WMGalleonState
{
    f32 savedX;
    f32 savedY;
    f32 savedZ;
    u8 mapEventsLatched;
    u8 pad0D;
    s16 savedYaw;
} WMGalleonState;

STATIC_ASSERT(sizeof(Dll1FBState) == 0xc);
STATIC_ASSERT(offsetof(Dll1FBState, baseMove) == 0x04);
STATIC_ASSERT(offsetof(Dll1FBState, triggerMode) == 0x06);
STATIC_ASSERT(offsetof(Dll1FBState, hideModel) == 0x09);
STATIC_ASSERT(sizeof(WMGalleonState) == 0x10);
STATIC_ASSERT(offsetof(WMGalleonState, savedX) == 0x00);
STATIC_ASSERT(offsetof(WMGalleonState, savedY) == 0x04);
STATIC_ASSERT(offsetof(WMGalleonState, savedZ) == 0x08);
STATIC_ASSERT(offsetof(WMGalleonState, mapEventsLatched) == 0x0C);
STATIC_ASSERT(offsetof(WMGalleonState, savedYaw) == 0x0E);
STATIC_ASSERT(offsetof(Dll1FBSetup, yawByte) == 0x18);
STATIC_ASSERT(offsetof(Dll1FBSetup, baseMove) == 0x19);
STATIC_ASSERT(offsetof(Dll1FBSetup, triggerMode) == 0x1a);
STATIC_ASSERT(offsetof(Dll1FBSetup, objectParam) == 0x1c);
STATIC_ASSERT(offsetof(WMGalleonSetup, yawByte) == 0x18);
STATIC_ASSERT(offsetof(WMSeqObjectSetup, yawByte) == 0x18);
STATIC_ASSERT(offsetof(WMSeqObjectSetup, setupType) == 0x19);

int LaserBeam_getExtraSize(void) { return 0x50; }
int LaserBeam_getObjectTypeId(void) { return 0; }

void LaserBeam_init(int* obj)
{
    void** state;

    state = (void**)OBJ_PTR(obj, 0xb8);
    (*gModgfxInterface)->detachSource(obj);
    if (state[0] != 0)
    {
        textureFree(state[0]);
        state[0] = 0;
    }
}

void LaserBeam_render(void)
{
}

void LaserBeam_hitDetect(void)
{
}

#include "main/audio/sfx_ids.h"
#include "main/game_object.h"
#include "main/resource.h"

typedef struct LaserBeamPlacement
{
    u8 pad0[0x1A - 0x0];
    s16 unk1A;
    u8 pad1C[0x1E - 0x1C];
    s16 unk1E;
    u8 pad20[0x4C - 0x20];
    u8 unk4C;
    u8 pad4D[0x2F8 - 0x4D];
    u8 unk2F8;
    u8 unk2F9;
    s8 unk2FA;
    u8 pad2FB[0x300 - 0x2FB];
} LaserBeamPlacement;

STATIC_ASSERT(offsetof(LaserBeamState, beamKind) == 0x4e);

/* pressureswitch_getExtraSize == 0x8. */

/* wmlasertarget_getExtraSize == 0x4. */

/* WM_colrise_getExtraSize == 0x4. */

/* wmtorch_getExtraSize == 0x10. */

/* lightsource_getExtraSize == 0x1c. */
typedef struct LightSourceState
{
    void* light;
    f32 fxTimer;
    u8 pad08[4];
    f32 sparkTimer;
    int gameBit; /* 0x10: -1 none */
    u8 mode; /* 0x14: 1 = hit-toggleable */
    u8 fxType;
    u8 fxArg;
    u8 lit; /* 0x17 */
    u8 litPrev;
    u8 sparks; /* 0x19 */
    u8 loopFlags; /* 0x1a: LightSourceFlagByte */
    u8 pad1B;
} LightSourceState;

STATIC_ASSERT(sizeof(LightSourceState) == 0x1c);

STATIC_ASSERT(sizeof(Dll200State) == 0x28);

extern undefined4 FUN_8000680c();
extern undefined4 FUN_80006824();
extern undefined8 FUN_80006ba8();
extern uint FUN_80006c00();
extern undefined4 FUN_8001771c();
extern u32 randomGetRange(int min, int max);
extern uint FUN_80017a98();
extern undefined4 ObjMsg_SendToObject();
extern int FUN_800632f4();

extern f32 lbl_803DC074;
extern f32 lbl_803E6A1C;
extern f32 lbl_803E6A20;
extern f32 lbl_803E6A24;
extern f32 lbl_803E6A80;

void LaserBeam_update(int obj2)
{
    extern undefined4 GameBit_Set(int eventId, int value); /* #57 */
    extern uint GameBit_Get(int eventId); /* #57 */
    extern void*Obj_GetPlayerObject(void);
    extern uint GameBit_Get(int id);
    extern void Sfx_PlayFromObject(int obj, int sfx);
    extern void Sfx_PlayAtPositionFromObject(int obj, f32 x, f32 y, f32 z, int sfx);
    extern int objGetAnimState80A(void* obj);
    extern f32 mathCosf(f32 x);
    extern f32 mathSinf(f32 x);
    extern int* lbl_803DDC80;
    extern u8 framesThisStep;
    extern f32 timeDelta;
    extern f32 lbl_803E5D10;
    extern f32 lbl_803E5D14;
    extern f32 lbl_803E5D18;
    extern f32 lbl_803E5D1C;
    extern f32 lbl_803E5D20;
    extern f32 lbl_803E5D24;
    extern f32 lbl_803E5D28;
    extern f32 lbl_803E5D2C;
    extern f32 lbl_803E5D30;
    extern f32 lbl_803E5D34;
    extern f32 lbl_803E5D38;
    extern f32 lbl_803E5D3C;
    extern f32 lbl_803E5D40;
    extern f32 lbl_803E5D44;
    extern f32 lbl_803E5D48;
    char* t;
    LaserBeamState* b;
    char* player;
    u8 c;
    int i;
    u16 sfx;
    f32 dz;
    f32 dz2;
    f32 sinv;
    f32 cosv;
    f32 range;
    f32 dot;
    f32 dy;
    f32 dx;
    f32 dzp;
    f32 a;
    f32 lat;
    f32 spread;
    f32 fz;

    t = *(char**)&((GameObject*)obj2)->anim.placementData;
    b = ((GameObject*)obj2)->extra;
    b->fireTimer -= framesThisStep;
    if (GameBit_Get(((LaserBeamPlacement*)t)->unk1E) == 0)
    {
        if (b->fireTimer < 0)
        {
            if (b->unk25 == 0)
            {
                c = b->beamKind;
                if (c == 3 || c == 30)
                {
                    b->fireTimer = b->firePeriod;
                }
                else
                {
                    if (c == 0 && b->emitterSlot != -1)
                    {
                        (*gModgfxInterface)->releaseHandle(&b->emitterSlot);
                    }
                    b->fireTimer = b->firePeriod;
                }
                b->sweepPhase = lbl_803E5D10;
            }
            else
            {
                b->fireTimer = 150;
            }
            b->active = 0;
        }
        else if (b->fireTimer < b->unk2E)
        {
            if (b->active == 0)
            {
                b->active = 1;
                c = b->beamKind;
                if (c == 1)
                {
                    if (lbl_803DDC80 != NULL)
                    {
                        (*(s16 (**)(int, int, int, int, int, int))(*lbl_803DDC80 + 4))(
                            obj2, 2, 0, 0x10004, -1, 0);
                    }
                }
                else if (c != 30 && c != 0)
                {
                    (*(s16 (**)(int, int, int, int, int, int))(*lbl_803DDC80 + 4))(
                        obj2, 0, 0, 0x10004, -1, 0);
                }
            }
            if (b->fireTimer < 0x28)
            {
                if (b->sweepPhase >= lbl_803E5D10 && b->unk25 == 0)
                {
                    b->sweepPhase = -(lbl_803E5D14 * timeDelta - b->sweepPhase);
                }
            }
            else if (b->fireTimer < 0x8c)
            {
                if (b->active == 1)
                {
                    b->active = 2;
                    c = b->beamKind;
                    if (c == 1)
                    {
                        if (lbl_803DDC80 != NULL)
                        {
                            (*(s16 (**)(int, int, int, int, int, int))(*lbl_803DDC80 + 4))(
                                obj2, 3, 0, 0x10004, -1, 0);
                        }
                    }
                    else if (c == 30)
                    {
                        if (lbl_803DDC80 != NULL)
                        {
                            b->emitterSlot =
                                (*(s16 (**)(int, int, int, int, int, int))(*lbl_803DDC80 + 4))(
                                    obj2, 30, 0, 0x10004, -1, 0);
                        }
                    }
                    else if (c != 0)
                    {
                        if (lbl_803DDC80 != NULL)
                        {
                            (*(s16 (**)(int, int, int, int, int, int))(*lbl_803DDC80 + 4))(
                                obj2, 1, 0, 0x10004, -1, 0);
                        }
                    }
                    else
                    {
                        if (lbl_803DDC80 != NULL && b->emitterSlot == -1)
                        {
                            if (b->emitterSlot != -1)
                            {
                                (*gModgfxInterface)->releaseHandle(&b->emitterSlot);
                            }
                            if (lbl_803DDC80 != NULL)
                            {
                                b->emitterSlot =
                                    (*(s16 (**)(int, int, int, int, int, int))(*lbl_803DDC80 + 4))(
                                        obj2, 0, 0, 0x10004, -1, 0);
                            }
                        }
                    }
                }
            }
            else if (b->sweepPhase <= lbl_803E5D18)
            {
                b->sweepPhase = lbl_803E5D1C * timeDelta + b->sweepPhase;
            }
        }
    }
    else if (b->beamKind == 0 && b->emitterSlot != -1)
    {
        (*gModgfxInterface)->releaseHandle(&b->emitterSlot);
    }
    dz = (f32)(int)((LaserBeamPlacement*)t)->unk1A;
    dz2 = dz * dz;
    sinv = mathCosf((lbl_803E5D20 * (f32)(int)*(s16*)obj2) / lbl_803E5D24);
    cosv = mathSinf((lbl_803E5D20 * (f32)(int)*(s16*)obj2) / lbl_803E5D24);
    dot = -(((GameObject*)obj2)->anim.localPosX * sinv + ((GameObject*)obj2)->anim.localPosZ * cosv);
    player = Obj_GetPlayerObject();
    b->unk27 = (s8)(b->unk27 - framesThisStep);
    if (b->unk27 <= 0)
    {
        b->unk27 = 0;
    }
    else if (b->beamKind == 0 && b->emitterSlot != -1)
    {
        (*gModgfxInterface)->releaseHandle(&b->emitterSlot);
    }
    if ((dot + (sinv * ((GameObject*)player)->anim.localPosX + cosv * ((GameObject*)player)->anim.localPosZ) >
            lbl_803E5D10 &&
            b->beamKind != 2) ||
        b->beamKind == 30)
    {
        b->sweepYaw -= framesThisStep;
        if (b->sweepYaw < 0)
        {
            b->sweepYaw = 0;
            b->unk25 = 0;
        }
    }
    else
    {
        b->sweepYaw += framesThisStep;
        if (b->sweepYaw > 60)
        {
            b->sweepYaw = 60;
            b->unk25 = 1;
        }
    }
    if (b->unk25 == 0)
    {
        b->unk24 = (u8)(b->active & 3);
    }
    else
    {
        b->unk24 = 2;
    }
    if (GameBit_Get(((LaserBeamPlacement*)t)->unk1E) != 0)
    {
        b->unk24 = 0;
    }
    if (b->unk27 == 0)
    {
        b->unk28 = 0;
    }
    if (player != NULL && b->unk27 == 0 && b->unk24 == 2)
    {
        range = lbl_803E5D28 + (f32)(int)*(s8*)&b->unk26;
        dy = ((GameObject*)player)->anim.localPosY - ((GameObject*)obj2)->anim.localPosY;
        if (dy < range && dy > -(lbl_803E5D2C + range))
        {
            dx = ((GameObject*)player)->anim.localPosX - ((GameObject*)obj2)->anim.localPosX;
            dzp = ((GameObject*)player)->anim.localPosZ - ((GameObject*)obj2)->anim.localPosZ;
            if (dx * dx + dzp * dzp < dz2)
            {
                lat = dot + (sinv * ((GameObject*)player)->anim.localPosX + cosv * ((GameObject*)player)->anim.
                    localPosZ);
                a = lat;
                if (lat < lbl_803E5D10)
                {
                    a = -lat;
                }
                if (a > lbl_803E5D30)
                {
                    a = lbl_803E5D30;
                }
                b->unk28 = (s16)(int)((lbl_803E5D30 - a) * lbl_803E5D34);
                if (!(lat < lbl_803E5D38 && lat > lbl_803E5D3C) && b->unk4C == 1)
                {
                    (*gModgfxInterface)->detachSource((void*)obj2);
                    b->unk4C = 0;
                }
                if (lat < range && lat > -range)
                {
                    if (objGetAnimState80A(player) == 0x1d7 && b->beamKind != 1)
                    {
                        GameBit_Set(0x468, 1);
                    }
                    else
                    {
                        if (dot + (sinv * ((GameObject*)player)->anim.previousLocalPosX +
                            cosv * ((GameObject*)player)->anim.previousLocalPosZ) < lbl_803E5D10)
                        {
                            spread = lbl_803E5D40;
                        }
                        else
                        {
                            spread = lbl_803E5D44;
                        }
                        Sfx_PlayAtPositionFromObject(obj2, ((GameObject*)player)->anim.localPosX,
                                                     ((GameObject*)obj2)->anim.localPosY,
                                                     ((GameObject*)player)->anim.localPosZ, 0x1c9);
                        if (*(s16*)(*(char**)&((GameObject*)player)->extra + 0x81a) == 0)
                        {
                            sfx = 31;
                        }
                        else
                        {
                            sfx = 35;
                        }
                        Sfx_PlayFromObject((int)player, sfx);
                        for (i = 0; i < 4; i++)
                        {
                            (*gPartfxInterface)->spawnObject(Obj_GetPlayerObject(), 0x198,
                                                             NULL, 4, -1, NULL);
                        }
                        b->targetX = sinv * spread + ((GameObject*)player)->anim.localPosX;
                        b->targetZ = cosv * spread + ((GameObject*)player)->anim.localPosZ;
                        c = b->beamKind;
                        if (c == 0 || c == 1)
                        {
                            ObjMsg_SendToObject(player, 0x60003, (char*)b + 0x34, 0);
                        }
                        else if ((u8)(c - 2) <= 1 || c == 30)
                        {
                            ObjMsg_SendToObject(player, 0x60004, (char*)b + 0x34, 0);
                        }
                        *(u8*)&b->unk27 = 2;
                    }
                }
            }
        }
    }
    if (b->unk24 == 0)
    {
        if (b->beamKind == 30 && b->emitterSlot != -1)
        {
            (*gModgfxInterface)->releaseHandle(&b->emitterSlot);
        }
        if (b->unk4C == 1)
        {
            (*gModgfxInterface)->detachSource((void*)obj2);
            b->unk4C = 0;
        }
    }
    fz = lbl_803E5D10;
    b->unk04 = fz;
    b->beamX = fz;
    b->beamZ = fz;
    b->unk08 = b->unk04;
    b->beamX2 = b->beamX;
    b->beamZ2 = b->beamZ + dz;
    b->unk26 = 8;
    ((GameObject*)obj2)->anim.currentMoveProgress = lbl_803E5D48 * timeDelta + ((GameObject*)obj2)->anim.
        currentMoveProgress;
    if (((GameObject*)obj2)->anim.currentMoveProgress > lbl_803E5D18)
    {
        ((GameObject*)obj2)->anim.currentMoveProgress = ((GameObject*)obj2)->anim.currentMoveProgress -
            lbl_803E5D18;
    }
}

void FUN_801f1634(undefined8 param_1, undefined8 param_2, undefined8 param_3, undefined8 param_4,
                  undefined8 param_5, undefined8 param_6, undefined8 param_7, undefined8 param_8,
                  uint param_9)
{
    char c;
    float entryY;
    float band;
    float riseVel;
    int iVar5;
    u8 phase;
    float* entry;
    uint buttons;
    int idx;
    float found;
    int i;
    undefined2* b;
    int local_18[3];

    b = ((GameObject*)param_9)->extra;
    iVar5 = FUN_80017a98();
    if (*(char*)((int)b + 5) == '\0')
    {
        phase = 0;
        if (((*(byte*)&((GameObject*)param_9)->anim.resetHitboxMode & 1) != 0) && (((GameObject*)param_9)->unkF8 == 0))
        {
            *b = 0;
            b[1] = 0x28;
            FUN_80006ba8(0, 0x100);
            phase = 1;
        }
        *(u8*)((int)b + 5) = phase;
        if (*(char*)((int)b + 5) != '\0')
        {
            *(u8*)(b + 3) = 1;
        }
        if (((GameObject*)param_9)->unkF8 == 0)
        {
            ObjHits_EnableObject(param_9);
            *(byte*)&((GameObject*)param_9)->anim.resetHitboxMode = *(byte*)&((GameObject*)param_9)->anim.
                resetHitboxMode & 0xf7;
            ((GameObject*)param_9)->anim.velocityY = -(lbl_803E6A1C * lbl_803DC074 - ((GameObject*)param_9)->anim.
                velocityY);
            ((GameObject*)param_9)->anim.localPosY =
                ((GameObject*)param_9)->anim.velocityY * lbl_803DC074 + ((GameObject*)param_9)->anim.localPosY;
            iVar5 = FUN_800632f4((double)((GameObject*)param_9)->anim.localPosX,
                                 (double)((GameObject*)param_9)->anim.localPosY,
                                 (double)((GameObject*)param_9)->anim.localPosZ, param_9, local_18, 0, 1);
            riseVel = lbl_803E6A24;
            band = lbl_803E6A20;
            found = 0.0;
            i = 0;
            idx = 0;
            if (0 < iVar5)
            {
                do
                {
                    entry = *(float**)(local_18[0] + idx);
                    if (*(char*)(entry + 5) != '\x0e')
                    {
                        entryY = *entry;
                        if ((((GameObject*)param_9)->anim.localPosY < entryY) &&
                            ((entryY - band < ((GameObject*)param_9)->anim.localPosY || (i == 0))))
                        {
                            found = entry[4];
                            ((GameObject*)param_9)->anim.localPosY = entryY;
                            ((GameObject*)param_9)->anim.velocityY = riseVel;
                        }
                    }
                    idx = idx + 4;
                    i = i + 1;
                    iVar5 = iVar5 + -1;
                }
                while (iVar5 != 0);
            }
            if (found != 0.0)
            {
                iVar5 = *(int*)((int)found + 0x58);
                c = *(char*)(iVar5 + 0x10f);
                *(char*)(iVar5 + 0x10f) = c + '\x01';
                *(uint*)(iVar5 + c * 4 + 0x100) = param_9;
            }
        }
    }
    else
    {
        ObjHits_DisableObject(param_9);
        *(byte*)&((GameObject*)param_9)->anim.resetHitboxMode = *(byte*)&((GameObject*)param_9)->anim.resetHitboxMode |
            8;
        buttons = FUN_80006c00(0);
        if ((buttons & 0x100) != 0)
        {
            *(u8*)(b + 3) = 0;
            FUN_80006ba8(0, 0x100);
        }
        if (((GameObject*)param_9)->unkF8 == 1)
        {
            *(u8*)((int)b + 5) = 2;
        }
        if ((*(char*)((int)b + 5) == '\x02') && (((GameObject*)param_9)->unkF8 == 0))
        {
            *(u8*)((int)b + 5) = 0;
            *(u8*)(b + 3) = 0;
        }
        if (*(char*)(b + 3) != '\0')
        {
            ObjMsg_SendToObject(iVar5, 0x100008, param_9, CONCAT22(b[1], *b));
        }
    }
    return;
}

void FUN_801f2b94(short* param_1)
{
    int handle;
    double dist;

    if (*(char*)(*(int*)(param_1 + 0x5c) + 0xc) == '\x02')
    {
        *param_1 = *param_1 + 0x32;
    }
    handle = FUN_80017a98();
    dist = (double)FUN_8001771c((float*)(handle + 0x18), (float*)(param_1 + 0xc));
    if ((double)lbl_803E6A80 <= dist)
    {
        FUN_8000680c((int)param_1, 0x40);
    }
    else
    {
        FUN_80006824((uint)param_1,SFXmn_eggylaugh216);
    }
    return;
}


extern void Sfx_PlayFromObject(int obj, int sfxId);

extern void* lbl_803DDC80;

void LaserBeam_initialise(void)
{
    lbl_803DDC80 = Resource_Acquire(0x81, 1);
}

void lightsource_hitDetect(void);

void LaserBeam_release(void)
{
    Resource_Release(lbl_803DDC80);
    lbl_803DDC80 = NULL;
}

void dll_1FF_init(s16* a, s8* b);

/* dll_1FF_render: when obj->_f8 implies
 * visible == -1 (else visible != 0), toggle bit 0x1000 of obj->_64->_30
 * based on obj->_b4 == -1, then call objRenderFn_8003b8f4. */

/* dll_200_render: when visible != 0 and
 * gMapEventInterface vtable[0x40] applied to obj->_ac returns 4, gate on
 * GameBit_Get(0x2bd); else render directly via objRenderFn_8003b8f4. */

/* dll_200_init: write a function pointer
 * (dll_200_SeqFn) into obj->_bc and prime obj->_b8 (the body block) with
 * fixed bytes, the three float position-quaternion from arg+8/c/10,
 * GameBit_Get(0xd0) latched into b->_24, plus several literal latches. */

#pragma opt_strength_reduction off

#pragma opt_strength_reduction off

extern int textureLoadAsset(int id);
extern f32 lbl_803E5D10;

void LaserBeam_free(s16* obj, char* arg)
{
    extern undefined8 ObjMsg_AllocQueue(); /* #57 */
    LaserBeamState* b;

    b = ((GameObject*)obj)->extra;
    ObjMsg_AllocQueue(obj, 2);
    *obj = (s16)((s32)*(s8*)(arg + 0x18) << 8);
    if (*(s16*)(arg + 0x1c) == 0)
    {
        b->firePeriod = (s16)(randomGetRange(-80, 80) + 400);
    }
    else
    {
        b->firePeriod = *(s16*)(arg + 0x1c);
    }
    b->fireTimer = b->firePeriod;
    b->active = 0;
    b->sweepPhase = lbl_803E5D10;
    b->beamKind = *(u8*)(arg + 0x19);
    b->unk2E = 0x118;
    b->emitterSlot = -1;
    if (b->beamKind == 30)
    {
        if (*(void**)&b->texture == NULL)
        {
            b->texture = textureLoadAsset(0x3e9);
        }
    }
    else if (b->beamKind == 1)
    {
        if (*(void**)&b->texture == NULL)
        {
            b->texture = textureLoadAsset(0x23d);
        }
    }
    else if (*(void**)&b->texture == NULL)
    {
        b->texture = textureLoadAsset(0xd9);
    }
}


typedef struct LightSourceFlagByte
{
    u8 looped : 1;
} LightSourceFlagByte;

#pragma opt_common_subs off
#pragma opt_common_subs reset
