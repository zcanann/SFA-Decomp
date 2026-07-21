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
#include "main/dll/dll_01FC_laserbeam.h"
#include "main/dll/modgfx_interface.h"
#include "main/texture.h"
#include "main/dll/partfx_interface.h"
#include "main/dll/dll1fbstate_struct.h"
#include "main/object_api.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_trig_api.h"
#include "main/dll/laserbeamstate_struct.h"
#include "main/dll/dll200state_struct.h"
#include "main/dll/LGT/dll_0206_lightsource.h"
#include "main/game_object.h"
#include "main/frame_timing.h"
#include "main/dll/player_api.h"
#include "main/obj_placement.h"
#include "main/resource.h"
#include "main/obj_message.h"
#include "main/gamebits.h"
#include "main/audio/sfx_play_api.h"
#include "main/audio/sfx_position_api.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/dll/dll1fbsetup_struct.h"
#include "main/dll/wmgalleonsetup_struct.h"
#include "main/dll/wmseqobjectsetup_struct.h"
#include "main/dll/wmgalleonstate_struct.h"
#include "main/gamebit_ids.h"
#include "main/dll/foodbag.h"

#define OBJ_PTR(obj, offset) (*(void**)((u8*)(obj) + (offset)))

#define LASERBEAM_MSG_PLAYER_HIT     0x60003 /* message the player on a standard beam hit */
#define LASERBEAM_MSG_PLAYER_BURST   0x60004 /* knock the player back with a burst hit */
#define LASERBEAM_PARTFX_HIT         0x198   /* spark burst spawned on the player when the beam connects */
#define LASERBEAM_MODGFX_RESOURCE_ID 0x81    /* modgfx beam effect resource -> gLaserBeamObjModgfxResource */
#define LASERBEAM_TEXTURE_KIND30     0x3e9   /* beam texture for beamKind 30 -> b->texture */
#define LASERBEAM_TEXTURE_KIND1      0x23d   /* beam texture for beamKind 1 -> b->texture */
#define LASERBEAM_TEXTURE_DEFAULT    0xd9    /* beam texture for other beamKinds -> b->texture */

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

int LaserBeam_getExtraSize(void)
{
    return 0x50;
}
int LaserBeam_getObjectTypeId(void)
{
    return 0;
}

void LaserBeam_free(int* obj)
{
    void** state;

    state = OBJ_PTR(obj, 0xb8);
    (*gModgfxInterface)->detachSource(obj);
    if (state[0] != 0)
    {
        textureFree((Texture*)(state[0]));
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
    ObjPlacement head; /* 0x00 */
    s8 spawnYaw;    /* 0x18: seeded into the object header (obj[0] = spawnYaw << 8) */
    u8 beamKind;    /* 0x19: laser variant (2/3/30) */
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

STATIC_ASSERT(sizeof(Dll200State) == 0x28);

static const f32 gLaserBeamObjPi = 3.1415927f;
static const f32 gLaserBeamObjAngleToRadScale = 32768.0f;

extern Dll81Interface** gLaserBeamObjModgfxResource;

void LaserBeam_update(int obj2)
{
    char* t;
    LaserBeamState* state;
    GameObject* player;
    u8 beamKind;
    int i;
    int sfx;
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
    state = ((GameObject*)obj2)->extra;
    state->fireTimer -= framesThisStep;
    if (mainGetBit(((LaserBeamPlacement*)t)->disableGameBit) == 0)
    {
        if (state->fireTimer < 0)
        {
            if (state->sweepDone == 0)
            {
                beamKind = state->beamKind;
                if (beamKind == 3 || beamKind == 30)
                {
                    state->fireTimer = state->firePeriod;
                }
                else
                {
                    if (beamKind == 0 && state->emitterSlot != -1)
                    {
                        (*gModgfxInterface)->releaseHandle(&state->emitterSlot);
                    }
                    state->fireTimer = state->firePeriod;
                }
                state->sweepPhase = 0.0f;
            }
            else
            {
                state->fireTimer = 150;
            }
            state->active = 0;
        }
        else if (state->fireTimer < state->fireTimerLimit)
        {
            if (state->active == 0)
            {
                state->active = 1;
                beamKind = state->beamKind;
                if (beamKind == 1)
                {
                    if (gLaserBeamObjModgfxResource != NULL)
                    {
                        (*gLaserBeamObjModgfxResource)->spawn(obj2, 2, NULL, 0x10004, -1, 0);
                    }
                }
                else if (beamKind != 30 && beamKind != 0)
                {
                    (*gLaserBeamObjModgfxResource)->spawn(obj2, 0, NULL, 0x10004, -1, 0);
                }
            }
            if (state->fireTimer < 0x28)
            {
                if (state->sweepPhase >= 0.0f && state->sweepDone == 0)
                {
                    state->sweepPhase = -(0.0026f * timeDelta - state->sweepPhase);
                }
            }
            else if (state->fireTimer < 0x8c)
            {
                if (state->active == 1)
                {
                    state->active = 2;
                    beamKind = state->beamKind;
                    if (beamKind == 1)
                    {
                        if (gLaserBeamObjModgfxResource != NULL)
                        {
                            (*gLaserBeamObjModgfxResource)->spawn(obj2, 3, NULL, 0x10004, -1, 0);
                        }
                    }
                    else if (beamKind == 30)
                    {
                        if (gLaserBeamObjModgfxResource != NULL)
                        {
                            state->emitterSlot =
                                (*gLaserBeamObjModgfxResource)->spawn(obj2, 30, NULL, 0x10004, -1, 0);
                        }
                    }
                    else if (beamKind != 0)
                    {
                        if (gLaserBeamObjModgfxResource != NULL)
                        {
                            (*gLaserBeamObjModgfxResource)->spawn(obj2, 1, NULL, 0x10004, -1, 0);
                        }
                    }
                    else
                    {
                        if (gLaserBeamObjModgfxResource != NULL && state->emitterSlot == -1)
                        {
                            if (state->emitterSlot != -1)
                            {
                                (*gModgfxInterface)->releaseHandle(&state->emitterSlot);
                            }
                            if (gLaserBeamObjModgfxResource != NULL)
                            {
                                state->emitterSlot =
                                    (*gLaserBeamObjModgfxResource)->spawn(obj2, 0, NULL, 0x10004, -1, 0);
                            }
                        }
                    }
                }
            }
            else if (state->sweepPhase <= 1.0f)
            {
                state->sweepPhase = 0.052f * timeDelta + state->sweepPhase;
            }
        }
    }
    else if (state->beamKind == 0 && state->emitterSlot != -1)
    {
        (*gModgfxInterface)->releaseHandle(&state->emitterSlot);
    }
    dz = (f32)(int)((LaserBeamPlacement*)t)->beamLength;
    dz2 = dz * dz;
    sinv = mathCosf((gLaserBeamObjPi * (f32)(int)((GameObject*)obj2)->anim.rotX) / gLaserBeamObjAngleToRadScale);
    cosv = mathSinf((gLaserBeamObjPi * (f32)(int)((GameObject*)obj2)->anim.rotX) / gLaserBeamObjAngleToRadScale);
    dot = -(((GameObject*)obj2)->anim.localPosX * sinv + ((GameObject*)obj2)->anim.localPosZ * cosv);
    player = Obj_GetPlayerObject();
    state->fireCooldown = (s8)(state->fireCooldown - framesThisStep);
    if (state->fireCooldown <= 0)
    {
        state->fireCooldown = 0;
    }
    else if (state->beamKind == 0 && state->emitterSlot != -1)
    {
        (*gModgfxInterface)->releaseHandle(&state->emitterSlot);
    }
    if ((dot + (sinv * ((GameObject*)player)->anim.localPosX + cosv * ((GameObject*)player)->anim.localPosZ) >
             0.0f &&
         state->beamKind != 2) ||
        state->beamKind == 30)
    {
        state->sweepYaw -= framesThisStep;
        if (state->sweepYaw < 0)
        {
            state->sweepYaw = 0;
            state->sweepDone = 0;
        }
    }
    else
    {
        state->sweepYaw += framesThisStep;
        if (state->sweepYaw > 60)
        {
            state->sweepYaw = 60;
            state->sweepDone = 1;
        }
    }
    if (state->sweepDone == 0)
    {
        state->beamState = (u8)(state->active & 3);
    }
    else
    {
        state->beamState = 2;
    }
    if (mainGetBit(((LaserBeamPlacement*)t)->disableGameBit) != 0)
    {
        state->beamState = 0;
    }
    if (state->fireCooldown == 0)
    {
        state->unk28 = 0;
    }
    if (player != NULL && state->fireCooldown == 0 && state->beamState == 2)
    {
        range = 5.0f + (f32)(int)*(s8*)&state->rangeOffset;
        dy = ((GameObject*)player)->anim.localPosY - ((GameObject*)obj2)->anim.localPosY;
        if (dy < range && dy > -(25.0f + range))
        {
            dx = ((GameObject*)player)->anim.localPosX - ((GameObject*)obj2)->anim.localPosX;
            dzp = ((GameObject*)player)->anim.localPosZ - ((GameObject*)obj2)->anim.localPosZ;
            if (dx * dx + dzp * dzp < dz2)
            {
                lat =
                    dot + (sinv * ((GameObject*)player)->anim.localPosX + cosv * ((GameObject*)player)->anim.localPosZ);
                a = lat;
                if (lat < 0.0f)
                {
                    a = -lat;
                }
                if (a > 63.0f)
                {
                    a = 63.0f;
                }
                tt = 63.0f - a;
                tt = 2.0f * tt;
                state->unk28 = (s16)(int)tt;
                if (!(lat < 70.0f && lat > -70.0f) && state->sourceAttached == 1)
                {
                    (*gModgfxInterface)->detachSource((void*)obj2);
                    state->sourceAttached = 0;
                }
                if (lat < range && lat > -range)
                {
                    if (objGetAnimState80A((GameObject*)(player)) == 0x1d7 && state->beamKind != 1)
                    {
                        mainSetBits(GAMEBIT_TRICKYCURVE_PLAYER_HIT, 1);
                    }
                    else
                    {
                        if (dot + (sinv * ((GameObject*)player)->anim.previousLocalPosX +
                                   cosv * ((GameObject*)player)->anim.previousLocalPosZ) <
                            0.0f)
                        {
                            spread = -20.0f;
                        }
                        else
                        {
                            spread = 20.0f;
                        }
                        Sfx_PlayAtPositionFromObject(
                            obj2, ((GameObject*)player)->anim.localPosX, ((GameObject*)obj2)->anim.localPosY,
                            ((GameObject*)player)->anim.localPosZ, SFXTRIG_wp_fball2_c_1c9);
                        if (*(s16*)(*(char**)&((GameObject*)player)->extra + 0x81a) == 0)
                        {
                            sfx = 31;
                        }
                        else
                        {
                            sfx = 35;
                        }
                        Sfx_PlayFromObject((u32)player, sfx);
                        for (i = 0; i < 4; i++)
                        {
                            (*gPartfxInterface)
                                ->spawnObject(Obj_GetPlayerObject(), LASERBEAM_PARTFX_HIT, NULL, 4, -1, NULL);
                        }
                        state->targetX = sinv * spread + ((GameObject*)player)->anim.localPosX;
                        state->targetZ = cosv * spread + ((GameObject*)player)->anim.localPosZ;
                        beamKind = state->beamKind;
                        if (beamKind == 0 || beamKind == 1)
                        {
                            ObjMsg_SendToObject(player, LASERBEAM_MSG_PLAYER_HIT, (char*)state + 0x34, 0);
                        }
                        else if ((u8)(beamKind - 2) <= 1 || beamKind == 30)
                        {
                            ObjMsg_SendToObject(player, LASERBEAM_MSG_PLAYER_BURST, (char*)state + 0x34, 0);
                        }
                        state->fireCooldown = 2;
                    }
                }
            }
        }
    }
    if (state->beamState == 0)
    {
        if (state->beamKind == 30 && state->emitterSlot != -1)
        {
            (*gModgfxInterface)->releaseHandle(&state->emitterSlot);
        }
        if (state->sourceAttached == 1)
        {
            (*gModgfxInterface)->detachSource((void*)obj2);
            state->sourceAttached = 0;
        }
    }
    fz = 0.0f;
    state->beamY = fz;
    state->beamX = fz;
    state->beamZ = fz;
    state->beamY2 = state->beamY;
    state->beamX2 = state->beamX;
    state->beamZ2 = state->beamZ + dz;
    state->rangeOffset = 8;
    ((GameObject*)obj2)->anim.currentMoveProgress =
        0.04f * timeDelta + ((GameObject*)obj2)->anim.currentMoveProgress;
    if (((GameObject*)obj2)->anim.currentMoveProgress > 1.0f)
    {
        ((GameObject*)obj2)->anim.currentMoveProgress = ((GameObject*)obj2)->anim.currentMoveProgress - 1.0f;
    }
}


void LaserBeam_init(s16* obj, char* arg)
{
    LaserBeamState* state;

    state = ((GameObject*)obj)->extra;
    ObjMsg_AllocQueue(obj, 2);
    *obj = (s16)((s32)((LaserBeamPlacement*)arg)->spawnYaw << 8);
    if (((LaserBeamPlacement*)arg)->firePeriod == 0)
    {
        state->firePeriod = (s16)(randomGetRange(-80, 80) + 400);
    }
    else
    {
        state->firePeriod = ((LaserBeamPlacement*)arg)->firePeriod;
    }
    state->fireTimer = state->firePeriod;
    state->active = 0;
    state->sweepPhase = 0.0f;
    state->beamKind = ((LaserBeamPlacement*)arg)->beamKind;
    state->fireTimerLimit = 0x118;
    state->emitterSlot = -1;
    if (state->beamKind == 30)
    {
        if (*(void**)&state->texture == NULL)
        {
            state->texture = textureLoadAsset(LASERBEAM_TEXTURE_KIND30);
        }
    }
    else if (state->beamKind == 1)
    {
        if (*(void**)&state->texture == NULL)
        {
            state->texture = textureLoadAsset(LASERBEAM_TEXTURE_KIND1);
        }
    }
    else if (*(void**)&state->texture == NULL)
    {
        state->texture = textureLoadAsset(LASERBEAM_TEXTURE_DEFAULT);
    }
}

void LaserBeam_release(void)
{
    Resource_Release(gLaserBeamObjModgfxResource);
    gLaserBeamObjModgfxResource = NULL;
}

void LaserBeam_initialise(void)
{
    gLaserBeamObjModgfxResource = Resource_Acquire(LASERBEAM_MODGFX_RESOURCE_ID, 1);
}
