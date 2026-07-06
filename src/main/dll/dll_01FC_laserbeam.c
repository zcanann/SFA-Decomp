/*
 * DLL 0x01FC (laserbeam) - WarpStone-City sweeping laser-beam hazard object.
 *
 * Object callbacks (LaserBeam_*): init/free set up the beam from its
 * placement (yaw byte, fire period, beamKind, texture asset chosen by
 * beamKind 1/30/other), initialise/release acquire+release the shared modgfx
 * effect resource (Resource_Acquire 0x81) into gLaserBeamObjModgfxResource. update() runs the
 * per-frame state machine: counts down fireTimer, drives the emitter through
 * the modgfx vtable (slot +4) per beamKind, sweeps the beam, projects the
 * player onto the beam axis (mathCosf/mathSinf of rotX), and on a hit plays
 * sfx + spawns partfx 0x198 and messages the player (ObjMsg 0x60003/0x60004).
 *
 * beamKind values seen: 0 (default modgfx emitter), 1 (texture 0x23d),
 * 2, 3, 30 (texture 0x3e9). The sibling setup/state structs (Dll1FBSetup,
 * WMGalleon*, WMSeqObjectSetup, LaserBeamPlacement, LightSourceState) document
 * the layouts of related objects shipped in the same DLL.
 */
#include "main/dll/dll1fbstate_struct.h"
#include "main/dll/laserbeamstate_struct.h"
#include "main/dll/dll200state_struct.h"
#include "main/effect_interfaces.h"
#include "main/game_object.h"
#include "main/obj_placement.h"
#include "main/resource.h"
#include "main/gameplay_runtime.h"
#include "main/objlib.h"
#include "main/gamebits.h"
#include "main/audio/sfx_trigger_ids.h"
extern void textureFree(u8* tex);
extern ModgfxInterface** gModgfxInterface;

#define OBJ_PTR(obj, offset) (*(void **)((u8 *)(obj) + (offset)))

#define LASERBEAM_MSG_PLAYER_BURST 0x60004 /* knock the player back with a burst hit */

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

    state = OBJ_PTR(obj, 0xb8);
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

typedef struct LaserBeamPlacement
{
    u8 pad0[0x18 - 0x0];
    s8 spawnYaw; /* 0x18: seeded into the object header (obj[0] = spawnYaw << 8) */
    u8 beamKind; /* 0x19: laser variant (2/3/30) */
    s16 beamLength; /* 0x1A: beam reach - added to beamZ for the endpoint and squared for the hit radius */
    s16 firePeriod; /* 0x1C: fire cadence override (0 = randomised) */
    s16 disableGameBit;
} LaserBeamPlacement;

STATIC_ASSERT(offsetof(LaserBeamPlacement, spawnYaw) == 0x18);
STATIC_ASSERT(offsetof(LaserBeamPlacement, beamKind) == 0x19);
STATIC_ASSERT(offsetof(LaserBeamPlacement, beamLength) == 0x1a);
STATIC_ASSERT(offsetof(LaserBeamPlacement, firePeriod) == 0x1c);
STATIC_ASSERT(offsetof(LaserBeamPlacement, disableGameBit) == 0x1e);

STATIC_ASSERT(offsetof(LaserBeamState, beamKind) == 0x4e);

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

/* .sdata2 constant pool */
static const f32 lbl_803E5D10 = 0.0f;
static const f32 lbl_803E5D14 = 0.0026f;
static const f32 lbl_803E5D18 = 1.0f;
static const f32 lbl_803E5D1C = 0.052f;
static const f32 gLaserBeamObjPi = 3.1415927f;
static const f32 gLaserBeamObjAngleToRadScale = 32768.0f;
static const f32 lbl_803E5D28 = 5.0f;
static const f32 lbl_803E5D2C = 25.0f;
static const f32 lbl_803E5D30 = 63.0f;
static const f32 lbl_803E5D34 = 2.0f;
static const f32 lbl_803E5D38 = 70.0f;
static const f32 lbl_803E5D3C = -70.0f;
static const f32 lbl_803E5D40 = -20.0f;
static const f32 lbl_803E5D44 = 20.0f;
static const f32 lbl_803E5D48 = 0.04f;

void LaserBeam_update(int obj2)
{

    extern void Sfx_PlayFromObject(int obj, int sfx);
    extern void Sfx_PlayAtPositionFromObject(int obj, f32 x, f32 y, f32 z, int sfx);
    extern int objGetAnimState80A(void* obj);
    extern float mathCosf(float x);
    extern float mathSinf(float x);
    extern int* gLaserBeamObjModgfxResource;
    extern u8 framesThisStep;
    extern f32 timeDelta;
    char* t;
    LaserBeamState* b;
    char* player;
    u8 beamKind;
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
    f32 tt;

    t = *(char**)&((GameObject*)obj2)->anim.placementData;
    b = ((GameObject*)obj2)->extra;
    b->fireTimer -= framesThisStep;
    if (GameBit_Get(((LaserBeamPlacement*)t)->disableGameBit) == 0)
    {
        if (b->fireTimer < 0)
        {
            if (b->sweepDone == 0)
            {
                beamKind = b->beamKind;
                if (beamKind == 3 || beamKind == 30)
                {
                    b->fireTimer = b->firePeriod;
                }
                else
                {
                    if (beamKind == 0 && b->emitterSlot != -1)
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
        else if (b->fireTimer < b->fireTimerLimit)
        {
            if (b->active == 0)
            {
                b->active = 1;
                beamKind = b->beamKind;
                if (beamKind == 1)
                {
                    if (gLaserBeamObjModgfxResource != NULL)
                    {
                        (*(s16 (**)(int, int, int, int, int, int))(*gLaserBeamObjModgfxResource + 4))(
                            obj2, 2, 0, 0x10004, -1, 0);
                    }
                }
                else if (beamKind != 30 && beamKind != 0)
                {
                    (*(s16 (**)(int, int, int, int, int, int))(*gLaserBeamObjModgfxResource + 4))(
                        obj2, 0, 0, 0x10004, -1, 0);
                }
            }
            if (b->fireTimer < 0x28)
            {
                if (b->sweepPhase >= lbl_803E5D10 && b->sweepDone == 0)
                {
                    b->sweepPhase = -(lbl_803E5D14 * timeDelta - b->sweepPhase);
                }
            }
            else if (b->fireTimer < 0x8c)
            {
                if (b->active == 1)
                {
                    b->active = 2;
                    beamKind = b->beamKind;
                    if (beamKind == 1)
                    {
                        if (gLaserBeamObjModgfxResource != NULL)
                        {
                            (*(s16 (**)(int, int, int, int, int, int))(*gLaserBeamObjModgfxResource + 4))(
                                obj2, 3, 0, 0x10004, -1, 0);
                        }
                    }
                    else if (beamKind == 30)
                    {
                        if (gLaserBeamObjModgfxResource != NULL)
                        {
                            b->emitterSlot =
                                (*(s16 (**)(int, int, int, int, int, int))(*gLaserBeamObjModgfxResource + 4))(
                                    obj2, 30, 0, 0x10004, -1, 0);
                        }
                    }
                    else if (beamKind != 0)
                    {
                        if (gLaserBeamObjModgfxResource != NULL)
                        {
                            (*(s16 (**)(int, int, int, int, int, int))(*gLaserBeamObjModgfxResource + 4))(
                                obj2, 1, 0, 0x10004, -1, 0);
                        }
                    }
                    else
                    {
                        if (gLaserBeamObjModgfxResource != NULL && b->emitterSlot == -1)
                        {
                            if (b->emitterSlot != -1)
                            {
                                (*gModgfxInterface)->releaseHandle(&b->emitterSlot);
                            }
                            if (gLaserBeamObjModgfxResource != NULL)
                            {
                                b->emitterSlot =
                                    (*(s16 (**)(int, int, int, int, int, int))(*gLaserBeamObjModgfxResource + 4))(
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
    dz = (f32)(int)((LaserBeamPlacement*)t)->beamLength;
    dz2 = dz * dz;
    sinv = mathCosf((gLaserBeamObjPi * (f32)(int)((GameObject*)obj2)->anim.rotX) / gLaserBeamObjAngleToRadScale);
    cosv = mathSinf((gLaserBeamObjPi * (f32)(int)((GameObject*)obj2)->anim.rotX) / gLaserBeamObjAngleToRadScale);
    dot = -(((GameObject*)obj2)->anim.localPosX * sinv + ((GameObject*)obj2)->anim.localPosZ * cosv);
    player = Obj_GetPlayerObject();
    b->fireCooldown = (s8)(b->fireCooldown - framesThisStep);
    if (b->fireCooldown <= 0)
    {
        b->fireCooldown = 0;
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
            b->sweepDone = 0;
        }
    }
    else
    {
        b->sweepYaw += framesThisStep;
        if (b->sweepYaw > 60)
        {
            b->sweepYaw = 60;
            b->sweepDone = 1;
        }
    }
    if (b->sweepDone == 0)
    {
        b->beamState = (u8)(b->active & 3);
    }
    else
    {
        b->beamState = 2;
    }
    if (GameBit_Get(((LaserBeamPlacement*)t)->disableGameBit) != 0)
    {
        b->beamState = 0;
    }
    if (b->fireCooldown == 0)
    {
        b->unk28 = 0;
    }
    if (player != NULL && b->fireCooldown == 0 && b->beamState == 2)
    {
        range = lbl_803E5D28 + (f32)(int)*(s8*)&b->rangeOffset;
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
                tt = lbl_803E5D30 - a;
                tt = lbl_803E5D34 * tt;
                b->unk28 = (s16)(int)tt;
                if (!(lat < lbl_803E5D38 && lat > lbl_803E5D3C) && b->sourceAttached == 1)
                {
                    (*gModgfxInterface)->detachSource((void*)obj2);
                    b->sourceAttached = 0;
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
                                                     ((GameObject*)player)->anim.localPosZ, SFXTRIG_wp_fball2_c_1c9);
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
                        beamKind = b->beamKind;
                        if (beamKind == 0 || beamKind == 1)
                        {
                            ObjMsg_SendToObject(player, 0x60003, (char*)b + 0x34, 0);
                        }
                        else if ((u8)(beamKind - 2) <= 1 || beamKind == 30)
                        {
                            ObjMsg_SendToObject(player, LASERBEAM_MSG_PLAYER_BURST, (char*)b + 0x34, 0);
                        }
                        *(u8*)&b->fireCooldown = 2;
                    }
                }
            }
        }
    }
    if (b->beamState == 0)
    {
        if (b->beamKind == 30 && b->emitterSlot != -1)
        {
            (*gModgfxInterface)->releaseHandle(&b->emitterSlot);
        }
        if (b->sourceAttached == 1)
        {
            (*gModgfxInterface)->detachSource((void*)obj2);
            b->sourceAttached = 0;
        }
    }
    fz = lbl_803E5D10;
    b->unk04 = fz;
    b->beamX = fz;
    b->beamZ = fz;
    b->unk08 = b->unk04;
    b->beamX2 = b->beamX;
    b->beamZ2 = b->beamZ + dz;
    b->rangeOffset = 8;
    ((GameObject*)obj2)->anim.currentMoveProgress = lbl_803E5D48 * timeDelta + ((GameObject*)obj2)->anim.
        currentMoveProgress;
    if (((GameObject*)obj2)->anim.currentMoveProgress > lbl_803E5D18)
    {
        ((GameObject*)obj2)->anim.currentMoveProgress = ((GameObject*)obj2)->anim.currentMoveProgress -
            lbl_803E5D18;
    }
}

#pragma opt_strength_reduction off

extern int textureLoadAsset(int id);

void LaserBeam_free(s16* obj, char* arg)
{
    LaserBeamState* b;

    b = ((GameObject*)obj)->extra;
    ObjMsg_AllocQueue(obj, 2);
    *obj = (s16)((s32)((LaserBeamPlacement*)arg)->spawnYaw << 8);
    if (((LaserBeamPlacement*)arg)->firePeriod == 0)
    {
        b->firePeriod = (s16)(randomGetRange(-80, 80) + 400);
    }
    else
    {
        b->firePeriod = ((LaserBeamPlacement*)arg)->firePeriod;
    }
    b->fireTimer = b->firePeriod;
    b->active = 0;
    b->sweepPhase = lbl_803E5D10;
    b->beamKind = ((LaserBeamPlacement*)arg)->beamKind;
    b->fireTimerLimit = 0x118;
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
#pragma opt_strength_reduction reset

extern void* gLaserBeamObjModgfxResource;

void LaserBeam_release(void)
{
    Resource_Release(gLaserBeamObjModgfxResource);
    gLaserBeamObjModgfxResource = NULL;
}

void LaserBeam_initialise(void)
{
    gLaserBeamObjModgfxResource = Resource_Acquire(0x81, 1);
}
