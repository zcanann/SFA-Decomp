/*
 * spiritdoorlock (DLL 0x167) - a spinning, glowing lock guarding a spirit
 * door, plus its ring of orbiting key objects.
 *
 * Behaviour:
 *  - Init places the lock, scales the model from the placement scale, hides
 *    its hits and (in mode 0) starts invisible with a red point light.
 *  - Update arms the lock when the player walks within range
 *    (GAMEBIT_K1_SPIRITDOORLOCK_PLAYER_APPROACHED) and the placement's
 *    activeGameBit is set: once active it drives a loop sfx, spins, and lays
 *    out the SPIRITDOORLOCK_ORBIT_OBJECT_GROUP objects evenly around itself
 *    (one step = 0x10000 / orbitCount), fades the model in, and scrolls its
 *    texture. When the orbit group empties the lock clears its active flag,
 *    sets the placement's doneGameBit and disables. While inactive-but-done
 *    it fades out, dims the point light and frees it.
 *
 * In-game this is the red "life force" seal in front of a gate: a
 * skull-and-crossbones at the centre (this lock) ringed by orbiting skulls.
 * Each skull is a group-SPIRITDOORLOCK_ORBIT_OBJECT_GROUP SpiritDoorSpirit
 * (DLL 0x157) and marks one monster you must kill in the area; killing the
 * monster sets that spirit's gateGameBit so its skull leaves the ring, and
 * when the ring empties the seal breaks (doneGameBit) and the gate opens.
 *
 * State lives in the obj extra block (SpiritDoorLockState); placement data is
 * SpiritDoorLockMapData. Both are defined in IMspacecraft.h.
 */
#include "main/audio/sfx_ids.h"
#include "main/camera_interface.h"
#include "main/game_object.h"
#include "main/objtexture.h"
#include "main/objseq.h"
#include "main/dll/IM/IMspacecraft.h"
#include "main/gamebits.h"
#include "main/objhits.h"
#include "main/audio/sfx.h"

/* per-file extern decls (homes: engine_shared / dll_80220608_shared /
   objhits / sky_80080E58_shared / gameplay_runtime); the spelling is
   load-bearing for codegen, so they stay local to this TU. */
extern int Obj_GetPlayerObject(void);
extern f32 Vec_distance(f32* a, f32* b);
extern f32 Vec_xzDistance(f32* a, f32* b);


extern int modelLightStruct_createPointLight(int obj, int a, int b, int c, int d);
extern void modelLightStruct_freeSlot(void** lightSlot);
extern void modelLightStruct_setDistanceAttenuation(u8* obj, f32 a, f32 b);
extern int* ObjGroup_GetObjects(int groupId, int* outCount);
extern void Obj_TransformLocalVectorByWorldMatrix(int obj, f32* in, f32* out);
extern void PSVECAdd(f32 * a, f32 * b, f32 * out);
extern void objRenderModelAndHitVolumes(int obj, int p2, int p3, int p4, int p5, f32 scale);
extern f32 timeDelta;
extern u8 framesThisStep;
extern int gSpiritDoorLockOrbitOffsetBase[4];
extern s16 gSpiritDoorLockSpinSpeed;
extern s32 gSpiritDoorLockTexScrollSpeed;
extern s32 gSpiritDoorLockTexScrollWrap;
extern f32 lbl_803E4430;
extern f32 gSpiritDoorLockDefaultScale;
extern f32 gSpiritDoorLockApproachRange;
extern f32 gSpiritDoorLockScaleFactor;
extern f32 gSpiritDoorLockScaleDecay;
extern f32 gSpiritDoorLockSpinDownRate;
extern f32 gSpiritDoorLockOrbitOffsetY;
extern const f32 gSpiritDoorLockOrbitMaxDist;

typedef struct { int a, b, c; } Vec3i;

void SpiritDoorLock_hitDetect(void)
{
}

void SpiritDoorLock_release(void)
{
}

void SpiritDoorLock_initialise(void)
{
}

int SpiritDoorLock_getExtraSize(void) { return SPIRITDOORLOCK_EXTRA_SIZE; }
int SpiritDoorLock_getObjectTypeId(void) { return 0x0; }

void SpiritDoorLock_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0) objRenderModelAndHitVolumes(p1, p2, p3, p4, p5, gSpiritDoorLockDefaultScale);
}

void SpiritDoorLock_free(int obj)
{
    SpiritDoorLockState* state = ((GameObject*)obj)->extra;
    if ((void*)state->light != NULL)
    {
        modelLightStruct_freeSlot((void*)&state->light);
    }
}

void SpiritDoorLock_init(int obj, SpiritDoorLockMapData* params, int mode)
{
    SpiritDoorLockState* state = ((GameObject*)obj)->extra;
    f32 scale;
    int atDefault;

    *(s16*)obj = (s16)(params->yaw << 8);
    state->orbitCount = params->orbitCount;
    state->active = 0;

    scale = params->scale * gSpiritDoorLockScaleFactor;
    atDefault = (scale != lbl_803E4430);
    atDefault = !atDefault;
    if (atDefault)
    {
        scale = gSpiritDoorLockDefaultScale;
    }
    ((GameObject*)obj)->anim.rootMotionScale = (*(f32**)&((GameObject*)obj)->anim.modelInstance)[1] * scale;
    state->spinAngle = 0;

    ObjHits_DisableObject(obj);
    ((struct { u8 bit80:1; } *)&state->flags)->bit80 = 0;

    if (mode == 0)
    {
        ((GameObject*)obj)->anim.alpha = 0;
        state->light = modelLightStruct_createPointLight(obj, 0xff, 0, 0x4d, 0);
    }
}

#pragma opt_loop_invariants off
void SpiritDoorLock_update(int obj)
{
    SpiritDoorLockState* state;
    SpiritDoorLockMapData* placement;
    int player;
    int orbitCount;
    f32 orbitOffset[3];
    f32 worldOffset[3];

    *(Vec3i*)orbitOffset = *(Vec3i*)gSpiritDoorLockOrbitOffsetBase;

    state = ((GameObject*)obj)->extra;
    placement = *(SpiritDoorLockMapData**)&((GameObject*)obj)->anim.placementData;

    player = Obj_GetPlayerObject();

    if (GameBit_Get(GAMEBIT_K1_SPIRITDOORLOCK_PLAYER_APPROACHED) == 0)
    {
        if (Vec_xzDistance(&((GameObject*)obj)->anim.worldPosX, &((GameObject*)player)->anim.worldPosX) < gSpiritDoorLockApproachRange)
        {
            if (state->active != 0)
            {
                (*gObjectTriggerInterface)->runSequence(0, (void*)obj, -1);
            }
            GameBit_Set(GAMEBIT_K1_SPIRITDOORLOCK_PLAYER_APPROACHED, 1);
        }
    }

    if (state->active == 0)
    {
        if (GameBit_Get(placement->doneGameBit) == 0)
        {
            state->active = GameBit_Get(placement->activeGameBit);
            if (state->active != 0)
            {
                f32 modelScale = (*(f32**)&((GameObject*)obj)->anim.modelInstance)[1] *
                    (f32)(int) placement->scale;
                ((GameObject*)obj)->anim.rootMotionScale =
                    modelScale * gSpiritDoorLockScaleFactor;
                if ((void*)state->light == NULL)
                {
                    state->light = modelLightStruct_createPointLight(obj, 0xff, 0, 0x4d, 0);
                }
            }
        }
        else
        {
            if (((GameObject*)obj)->anim.alpha == 255)
            {
                Sfx_PlayFromObject(0, SFXsp_lf_mutter4);
            }
            if (((GameObject*)obj)->anim.alpha != 0)
            {
                ((GameObject*)obj)->anim.alpha -= 1;
                if ((void*)state->light != NULL)
                {
                    u32 atten = (u32)((GameObject*)obj)->anim.alpha >> 2;
                    modelLightStruct_setDistanceAttenuation((void*)state->light, (f32)(int)atten,
                                                            (f32)(int)(atten + 10));
                }
                ((GameObject*)obj)->anim.rootMotionScale *= gSpiritDoorLockScaleDecay;
                ((GameObject*)obj)->anim.rotZ =
                    (f32)(int)((GameObject*)obj)->anim.rotZ - gSpiritDoorLockSpinDownRate * timeDelta;
            }
            else
            {
                if ((void*)state->light != NULL)
                {
                    modelLightStruct_freeSlot((void*)&state->light);
                }
            }
        }
    }
    else
    {
        int camMode;
        int* orbitObjs;
        ObjTextureRuntimeSlot* tex;
        s16 angleStep;
        s16 angle;
        int i;
        f32 maxDist;
        camMode = (*gCameraInterface)->getMode();
        if (camMode != 0x51)
        {
            Sfx_KeepAliveLoopedObjectSound(obj, SPIRITDOORLOCK_LOOP_SFX);
        }
        orbitObjs = ObjGroup_GetObjects(SPIRITDOORLOCK_ORBIT_OBJECT_GROUP, &orbitCount);
        angleStep = 0x10000 / state->orbitCount;
        angle = state->spinAngle;
        orbitOffset[1] = gSpiritDoorLockOrbitOffsetY;
        for (i = 0; i < orbitCount; i++)
        {
            if (Vec_distance(&((GameObject*)obj)->anim.worldPosX, &((GameObject*)orbitObjs[i])->anim.worldPosX) > gSpiritDoorLockOrbitMaxDist)
            {
                continue;
            }
            ((GameObject*)obj)->anim.rotZ = angle;
            Obj_TransformLocalVectorByWorldMatrix(obj, orbitOffset, worldOffset);
            PSVECAdd(&((GameObject*)obj)->anim.localPosX, worldOffset, &((GameObject*)orbitObjs[i])->anim.localPosX);
            ((GameObject*)orbitObjs[i])->anim.rotX = ((GameObject*)obj)->anim.rotX;
            ((GameObject*)orbitObjs[i])->anim.rotZ = (s16)(angle + 0x8000);
            ((GameObject*)orbitObjs[i])->anim.rootMotionScale = ((GameObject*)obj)->anim.rootMotionScale;
            angle += angleStep;
        }
        state->spinAngle += gSpiritDoorLockSpinSpeed;
        ((GameObject*)obj)->anim.rotZ = 0;
        if (orbitCount == 0)
        {
            state->active = 0;
            GameBit_Set(placement->doneGameBit, 1);
            ObjHits_DisableObject(obj);
        }
        tex = objFindTexture((void*)obj, 0, 0);
        if (tex != NULL)
        {
            tex->offsetT = (s16)(tex->offsetT + gSpiritDoorLockTexScrollSpeed * framesThisStep);
            tex->offsetS = (s16)(tex->offsetS + gSpiritDoorLockTexScrollSpeed * framesThisStep);
            if ((s32)tex->offsetT > (s32)(gSpiritDoorLockTexScrollWrap << 8))
            {
                tex->offsetT = (s16)(tex->offsetT - (gSpiritDoorLockTexScrollWrap << 8));
            }
            if ((s32)tex->offsetS > (s32)(gSpiritDoorLockTexScrollWrap << 8))
            {
                tex->offsetS = (s16)(tex->offsetS - (gSpiritDoorLockTexScrollWrap << 8));
            }
        }
        if (((GameObject*)obj)->anim.alpha < 0xff)
        {
            ((GameObject*)obj)->anim.alpha += 1;
        }
    }
}
#pragma opt_loop_invariants reset
