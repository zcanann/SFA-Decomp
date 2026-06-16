#include "main/audio/sfx_ids.h"
#include "main/camera_interface.h"
#include "main/game_object.h"
#include "main/objtexture.h"
#include "main/objseq.h"
#include "main/dll/IM/IMspacecraft.h"

extern int Obj_GetPlayerObject(void);
extern f32 Vec_distance(f32 * a, f32 * b);
extern f32 Vec_xzDistance(f32 * a, f32 * b);
extern void Sfx_PlayFromObject(int obj, int sfxId);
extern void Sfx_KeepAliveLoopedObjectSound(int obj, int sfxId);
extern u32 GameBit_Get(int eventId);
extern void GameBit_Set(int eventId, int value);

extern int modelLightStruct_createPointLight(int obj, int a, int b, int c, int d);
extern void modelLightStruct_freeSlot(void* p);
extern void modelLightStruct_setDistanceAttenuation(void* p, f32 a, f32 b);

extern void ObjHits_DisableObject(int obj);
extern int* ObjGroup_GetObjects(int groupId, int* outCount);
extern void Obj_TransformLocalVectorByWorldMatrix(int obj, f32* in, f32* out);
extern void PSVECAdd(f32 * a, f32 * b, f32 * out);

extern void objRenderFn_8003b8f4(f32 v);

extern f32 timeDelta;
extern u8 framesThisStep;
extern int lbl_802C22F8[4];
extern s16 lbl_803DBED0;
extern s32 lbl_803DBED4;
extern s32 lbl_803DBED8;

extern f32 lbl_803E4430;
extern f32 lbl_803E4440;
extern f32 lbl_803E4444;
extern f32 lbl_803E4448;
extern f32 lbl_803E444C;
extern f32 lbl_803E4450;
extern f32 lbl_803E4454;
extern f32 lbl_803E4458;

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
    if (v != 0) objRenderFn_8003b8f4(lbl_803E4440);
}


void SpiritDoorLock_free(int obj)
{
    SpiritDoorLockState* state = ((GameObject*)obj)->extra;
    if ((void*)state->light != NULL)
    {
        modelLightStruct_freeSlot(state);
    }
}


void SpiritDoorLock_init(int obj, SpiritDoorLockMapData* params, int mode)
{
    SpiritDoorLockState* state = ((GameObject*)obj)->extra;
    f32 mult;
    int isLess;

    ((GameObject*)obj)->anim.rotX = (s16)(params->yaw << 8);
    state->orbitCount = params->orbitCount;
    state->active = 0;

    mult = (f32)params->scale * lbl_803E4448;
    isLess = (mult != lbl_803E4430);
    isLess = !isLess;
    if (isLess)
    {
        mult = lbl_803E4440;
    }
    ((GameObject*)obj)->anim.rootMotionScale = (*(f32**)&((GameObject*)obj)->anim.modelInstance)[1] * mult;
    state->spinAngle = 0;

    ObjHits_DisableObject(obj);
    ((struct { u8 bit80:1; } *)&state->flags)->bit80 = 0;

    if (mode == 0)
    {
        ((GameObject*)obj)->anim.alpha = 0;
        state->light = modelLightStruct_createPointLight(obj, 255, 0, 77, 0);
    }
}

#pragma opt_loop_invariants off
void SpiritDoorLock_update(int obj)
{
    SpiritDoorLockState* state;
    SpiritDoorLockMapData* descriptor;
    int player;
    int local_68;
    f32 local_58[3];
    f32 local_5c[3];

    *(Vec3i*)local_58 = *(Vec3i*)lbl_802C22F8;

    state = ((GameObject*)obj)->extra;
    descriptor = *(SpiritDoorLockMapData**)&((GameObject*)obj)->anim.placementData;

    player = Obj_GetPlayerObject();

    if (GameBit_Get(SPIRITDOORLOCK_GAMEBIT_PLAYER_APPROACHED) == 0)
    {
        if (Vec_xzDistance(&((GameObject*)obj)->anim.worldPosX, &((GameObject*)player)->anim.worldPosX) < lbl_803E4444)
        {
            if (state->active != 0)
            {
                (*gObjectTriggerInterface)->runSequence(0, (void*)obj, -1);
            }
            GameBit_Set(SPIRITDOORLOCK_GAMEBIT_PLAYER_APPROACHED, 1);
        }
    }

    if (state->active == 0)
    {
        if (GameBit_Get(descriptor->doneGameBit) == 0)
        {
            state->active = GameBit_Get(descriptor->activeGameBit);
            if (state->active != 0)
            {
                {
                    f32 base = (*(f32**)&((GameObject*)obj)->anim.modelInstance)[1] *
                        (f32)(int)descriptor->scale;
                    ((GameObject*)obj)->anim.rootMotionScale = base * lbl_803E4448;
                }
                if (state->light == 0u)
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
                if (state->light != 0)
                {
                    u32 b = (u32)((GameObject*)obj)->anim.alpha >> 2;
                    modelLightStruct_setDistanceAttenuation((void*)state->light, (f32)(int)b,
                                                            (f32)(int)(b + 10));
                }
                ((GameObject*)obj)->anim.rootMotionScale *= lbl_803E444C;
                ((GameObject*)obj)->anim.rotZ =
                    (s16)(s32)((f32)(int)((GameObject*)obj)->anim.rotZ - lbl_803E4450 * timeDelta);
            }
            else
            {
                if (state->light != 0)
                {
                    modelLightStruct_freeSlot(state);
                }
            }
        }
    }
    else
    {
        int cam_state;
        int* list_ptr;
        ObjTextureRuntimeSlot* piTex;
        int i;
        int angle;
        int stride;
        f32 max_dist;
        cam_state = (*gCameraInterface)->getMode();
        if (cam_state != 0x51)
        {
            Sfx_KeepAliveLoopedObjectSound(obj, SPIRITDOORLOCK_LOOP_SFX);
        }
        list_ptr = ObjGroup_GetObjects(SPIRITDOORLOCK_ORBIT_OBJECT_GROUP, &local_68);
        stride = (s16)(0x10000 / state->orbitCount);
        angle = (s16)state->spinAngle;
        local_58[1] = lbl_803E4454;
        max_dist = lbl_803E4458;
        for (i = 0; i < local_68; i++)
        {
            if (Vec_distance(&((GameObject*)obj)->anim.worldPosX, (f32*)((char*)list_ptr[i] + 0x18)) > max_dist)
            {
                continue;
            }
            ((GameObject*)obj)->anim.rotZ = (s16)angle;
            Obj_TransformLocalVectorByWorldMatrix(obj, local_58, local_5c);
            PSVECAdd(&((GameObject*)obj)->anim.localPosX, local_5c, (f32*)((char*)list_ptr[i] + 0xc));
            *(s16*)list_ptr[i] = ((GameObject*)obj)->anim.rotX;
            *(s16*)((char*)list_ptr[i] + 4) = (s16)(angle + 0x8000);
            *(f32*)((char*)list_ptr[i] + 8) = ((GameObject*)obj)->anim.rootMotionScale;
            angle += stride;
        }
        state->spinAngle += (int)lbl_803DBED0;
        ((GameObject*)obj)->anim.rotZ = 0;
        if (local_68 == 0)
        {
            state->active = 0;
            GameBit_Set(descriptor->doneGameBit, 1);
            ObjHits_DisableObject(obj);
        }
        piTex = objFindTexture((void*)obj, 0, 0);
        if (piTex != NULL)
        {
            piTex->offsetT = (s16)(piTex->offsetT + lbl_803DBED4 * (s32)framesThisStep);
            piTex->offsetS = (s16)(piTex->offsetS + lbl_803DBED4 * (s32)framesThisStep);
            if ((s32)piTex->offsetT > (s32)(lbl_803DBED8 << 8))
            {
                piTex->offsetT = (s16)(piTex->offsetT - (lbl_803DBED8 << 8));
            }
            if ((s32)piTex->offsetS > (s32)(lbl_803DBED8 << 8))
            {
                piTex->offsetS = (s16)(piTex->offsetS - (lbl_803DBED8 << 8));
            }
        }
        if (((GameObject*)obj)->anim.alpha < 0xff)
        {
            ((GameObject*)obj)->anim.alpha += 1;
        }
    }
}
#pragma opt_loop_invariants reset

