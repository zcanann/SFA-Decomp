#include "main/audio/sfx_ids.h"
#include "main/dll/objfsa.h"
#include "main/dll/rom_curve_interface.h"
#include "main/game_object.h"
#include "main/dll/IM/IMspacecraft.h"
#include "main/audio/sfx.h"
#include "main/sfa_shared_decls.h"
#include "main/audio/sfx_trigger_ids.h"
#define ROLLINGBARREL_OBJFLAG_PARENT_SLACK 0x1000
extern int Obj_GetPlayerObject(void);
extern f32 Vec_distance(f32* a, f32* b);
extern int randomGetRange(int lo, int hi);


extern int getAngle(float y, float x);
extern void ObjHitbox_SetSphereRadius(int obj, int r);
extern void ObjHits_SetHitVolumeSlot(int obj, u8 slot, int a, int b);
extern void ObjHits_DisableObject(u32 objPtr);
extern void ObjHits_EnableObject(u32 objPtr);
extern int ObjHits_GetPriorityHit(int obj, int* outHitObject, int* outSphereIndex, u32* outHitVolume);
extern int* ObjGroup_GetObjects(int groupId, int* outCount);
extern void ObjGroup_RemoveObject(int obj, int groupId);
extern void ObjGroup_AddObject(u32 obj, int group);
extern void Obj_FreeObject(int obj);
extern void spawnExplosion(int obj, int p2, int p3, int p4, int p5, int p6, int p7, int p8, f32 size);


extern void objRenderFn_8003b8f4(int* obj);
extern f32 timeDelta;
extern s16 gRollingBarrelExplodingCount;
extern int gRollingBarrelCurveInitPair;
typedef struct { int a, b; } RollingBarrelInitPair;
extern const f32 lbl_803E4468;
extern const f32 lbl_803E446C;
extern const f32 gRollingBarrelShakeMaxDist;
extern const f32 lbl_803E4474;
extern const f32 lbl_803E4478;
extern const f32 lbl_803E447C;
extern const f32 lbl_803E4480;
extern const f32 lbl_803E4484;
extern const f32 gRollingBarrelGravity;
extern const f32 gRollingBarrelFallLimitY;
extern const f32 gRollingBarrelBounceFactor;
extern const f32 lbl_803E44A4;
extern const f32 lbl_803E44A8;
extern const f32 lbl_803E44AC;
extern const f32 lbl_803E44B0;
extern const f32 lbl_803E44B4;
extern f32 gRollingBarrelCurveInitData;

void RollingBarrel_hitDetect(void)
{
}

void RollingBarrel_release(void)
{
}

int RollingBarrel_getExtraSize(void) { return ROLLINGBARREL_EXTRA_SIZE; }
int RollingBarrel_getObjectTypeId(void) { return 0x0; }

void RollingBarrel_initialise(void) { gRollingBarrelExplodingCount = 0x0; }

void RollingBarrel_render(int obj, int p1, int p2, int p3, int p4, s8 visible)
{
    RollingBarrelState* state = ((GameObject*)obj)->extra;
    if (visible == 0 || state->state >= ROLLINGBARREL_STATE_EXPLODED_WAIT)
    {
        return;
    }

    ((void(*)(int, int, int, int, int, f32))objRenderFn_8003b8f4)(obj, p1, p2, p3, p4, lbl_803E4474);
}

void RollingBarrel_free(int obj)
{
    RollingBarrelState* state = ((GameObject*)obj)->extra;
    int count;
    int* arr = ObjGroup_GetObjects(ROLLINGBARREL_GROUP_ID, &count);
    int i;
    u32 a;
    for (i = 0; i < count; i++)
    {
        a = arr[i];
        if (a == obj)
        {
            ObjGroup_RemoveObject(obj, ROLLINGBARREL_GROUP_ID);
            break;
        }
    }
    if (state->state == ROLLINGBARREL_STATE_EXPLODED_WAIT)
    {
        gRollingBarrelExplodingCount -= 1;
    }
}

void RollingBarrel_init(int obj, RollingBarrelMapData* params)
{
    RollingBarrelState* state = ((GameObject*)obj)->extra;
    int tmp[2];

    *(RollingBarrelInitPair*)tmp = *(RollingBarrelInitPair*)&gRollingBarrelCurveInitPair;
    params->respawnParam = -1;
    ((GameObject*)obj)->anim.flags = (s16)(((GameObject*)obj)->anim.flags & ~OBJANIM_FLAG_HIDDEN);
    ((GameObject*)obj)->anim.rotZ = 0x4000;

    ((GameObject*)obj)->anim.localPosX = params->x;
    ((GameObject*)obj)->anim.worldPosX = params->x;
    ((GameObject*)obj)->anim.localPosY = params->y;
    ((GameObject*)obj)->anim.worldPosY = params->y;
    ((GameObject*)obj)->anim.localPosZ = params->z;
    ((GameObject*)obj)->anim.worldPosZ = params->z;

    state->verticalSpeed = params->verticalSpeed / lbl_803E447C;
    state->curveSpeed = params->curveSpeed / lbl_803E447C;
    state->state = ROLLINGBARREL_STATE_ROLLING;
    state->pitchRising = 1;
    state->timer = lbl_803E4468;

    (*gRomCurveInterface)->initCurve(&state->curve, (void*)obj, gRollingBarrelCurveInitData, tmp, -1);
}

void RollingBarrel_update(int obj)
{
    RollingBarrelState* state;
    RollingBarrelMapData* descriptor;
    f32 floor_y;
    f32 dist_sq;
    int blocked;
    int hitInfo;
    int hitB;
    u32 hitC;
    int hitResult;
    u32 r;
    u8 stateId;

    state = ((GameObject*)obj)->extra;
    hitInfo = 0;
    descriptor = *(RollingBarrelMapData**)&((GameObject*)obj)->anim.placementData;
    blocked = 0;
    dist_sq = lbl_803E4468;
    stateId = state->state;

    switch (stateId)
    {
    case ROLLINGBARREL_STATE_ROLLING:
        {
            if (descriptor->objectDefId == ROLLINGBARREL_SPECIAL_DESCRIPTOR_TYPE)
            {
                f32 vmax = lbl_803E446C;
                while (blocked == 0 && dist_sq < vmax * timeDelta)
                {
                    blocked = Curve_AdvanceAlongPath(&state->curve, state->curveSpeed);
                    if (blocked == 0 && state->curve.atSegmentEnd != 0)
                    {
                        (*gRomCurveInterface)->goNextPoint(&state->curve);
                    }
                    {
                        f32 dx = state->curve.posX - ((GameObject*)obj)->anim.previousLocalPosX;
                        f32 dz = state->curve.posZ - ((GameObject*)obj)->anim.previousLocalPosZ;
                        dist_sq = dx * dx + dz * dz;
                    }
                }
            }
            else
            {
                blocked = Curve_AdvanceAlongPath(&state->curve, state->curveSpeed);
                if (blocked == 0 && state->curve.atSegmentEnd != 0)
                {
                    (*gRomCurveInterface)->goNextPoint(&state->curve);
                }
            }

            state->hitVolumeSlot = 10;
            ObjHitbox_SetSphereRadius(obj, ((GameObject*)obj)->anim.modelInstance->primaryHitboxRadius);

            if (descriptor->objectDefId == ROLLINGBARREL_SPECIAL_DESCRIPTOR_TYPE)
            {
                floor_y = lbl_803E4478 + state->curve.posY;
            }
            else
            {
                floor_y = state->curve.posY;
            }

            state->verticalSpeed = gRollingBarrelGravity * timeDelta + state->verticalSpeed;
            ((GameObject*)obj)->anim.localPosY =
                state->verticalSpeed * timeDelta + ((GameObject*)obj)->anim.localPosY;

            if (((GameObject*)obj)->anim.localPosY < floor_y)
            {
                if (descriptor->objectDefId == ROLLINGBARREL_SPECIAL_DESCRIPTOR_TYPE &&
                    ((GameObject*)obj)->anim.localPosY < gRollingBarrelFallLimitY)
                {
                    blocked = 1;
                }
                if (blocked == 0 &&
                    state->verticalSpeed * state->verticalSpeed > lbl_803E446C)
                {
                    Sfx_PlayFromObjectLimited(obj, SFXTRIG_mfin2_c, 6);
                }
                state->verticalSpeed *= gRollingBarrelBounceFactor;
                ((GameObject*)obj)->anim.localPosY = lbl_803E44A4 * floor_y - ((GameObject*)obj)->anim.localPosY;
            }
            ((GameObject*)obj)->anim.localPosX = state->curve.posX;
            ((GameObject*)obj)->anim.localPosZ = state->curve.posZ;
            *(s16*)obj = (s16)getAngle(state->curve.tangentX, state->curve.tangentZ);

            if (state->pitchRising != 0)
            {
                ((GameObject*)obj)->anim.rotZ =
                    (s16)(lbl_803E44A8 * timeDelta + (f32)(int)((GameObject*)obj)->anim.rotZ);
                if (((GameObject*)obj)->anim.rotZ > 0x5000)
                {
                    state->pitchRising = 0;
                }
            }
            else
            {
                ((GameObject*)obj)->anim.rotZ =
                    (s16) - (lbl_803E44A8 * timeDelta - (f32)(int)((GameObject*)obj)->anim.rotZ);
                if (((GameObject*)obj)->anim.rotZ < 0x3a00)
                {
                    state->pitchRising = 1;
                }
            }

            {
                f32 rotYStep = lbl_803E44AC * timeDelta;
                ((GameObject*)obj)->anim.rotY =
                    (s16)(rotYStep * state->curveSpeed +
                        (f32)(int)((GameObject*)obj)->anim.rotY);
            }
            hitResult = ObjHits_GetPriorityHit(obj, &hitInfo, &hitB, &hitC);

            if (blocked != 0 || (void*)hitInfo == (void*)Obj_GetPlayerObject() || (u32)(hitResult - 0xe) <= 1u ||
                hitResult == 0x13)
            {
                if (blocked == 0)
                {
                    state->hitVolumeSlot = 0;
                }
                else
                {
                    state->hitVolumeSlot = 5;
                }
                r = randomGetRange(0, 2);
                fn_801A5D88(obj, r);
            }
        }
        break;
    case ROLLINGBARREL_STATE_EXPLODED_WAIT:
        state->timer += timeDelta;
        if (state->timer >= lbl_803E44B0)
        {
            state->state = ROLLINGBARREL_STATE_RESPAWN_WAIT;
            state->timer -= lbl_803E44B0;
        }
        break;
    case ROLLINGBARREL_STATE_RESPAWN_WAIT:
        state->timer += timeDelta;
        if (state->timer >= lbl_803E44B0)
        {
            state->hitVolumeSlot = 0;
            state->state = ROLLINGBARREL_STATE_CLEANUP;
            state->timer -= lbl_803E44B0;
            ObjGroup_AddObject(obj, ROLLINGBARREL_GROUP_ID);
            gRollingBarrelExplodingCount -= 1;
        }
        break;
    case ROLLINGBARREL_STATE_CLEANUP:
        state->timer += timeDelta;
        if (state->timer >= lbl_803E44B4)
        {
            Obj_FreeObject(obj);
            return;
        }
        break;
    }

    if (state->hitVolumeSlot != 0)
    {
        ObjHits_EnableObject(obj);
        ObjHits_SetHitVolumeSlot(obj, state->hitVolumeSlot, 1, 0);
    }
    else
    {
        ObjHits_DisableObject(obj);
        ObjHits_SetHitVolumeSlot(obj, state->hitVolumeSlot, 0, 0);
    }
}

void fn_801A5D88(int obj, int explosionVariant)
{
    RollingBarrelState* state = ((GameObject*)obj)->extra;
    u32 r;
    u32 r2;
    int player;
    f32 dist;
    f32 falloff;
    gRollingBarrelExplodingCount += 1;
    Sfx_PlayFromObject(obj, SFXsp_lf_mutter1);
    if (gRollingBarrelExplodingCount > 1)
    {
        r = randomGetRange(0, 1) & 0xff;
        spawnExplosion(obj, 1, 1, 0, r, 0, 0, 0, (f32)(int)randomGetRange(0x32, 0x3c));
    }
    else
    {
        r = randomGetRange(0, 1) & 0xff;
        spawnExplosion(obj, 1, 1, 0, r, 0, 1, 0, (f32)(int)randomGetRange(0x32, 0x3c));
    }
    state->state = ROLLINGBARREL_STATE_EXPLODED_WAIT;
    state->timer = lbl_803E4468;
    ((GameObject*)obj)->anim.flags = (s16)(((GameObject*)obj)->anim.flags | OBJANIM_FLAG_HIDDEN);
    ObjHitbox_SetSphereRadius(obj,
                              (s32)(lbl_803E446C * (f32)(u32)((GameObject*)obj)->anim.modelInstance->primaryHitboxRadius));
    player = Obj_GetPlayerObject();
    if ((((GameObject*)player)->objectFlags & ROLLINGBARREL_OBJFLAG_PARENT_SLACK) == 0)
    {
        dist = Vec_distance(&((GameObject*)obj)->anim.worldPosX, &((GameObject*)player)->anim.worldPosX);
        if (dist <= gRollingBarrelShakeMaxDist)
        {
            falloff = lbl_803E4474 - dist / gRollingBarrelShakeMaxDist;
            CameraShake_Start(lbl_803E4478 * falloff, lbl_803E447C * falloff, lbl_803E4480);
            doRumble(lbl_803E4484 * falloff);
        }
    }
}
