/*
 * DLL 0x150 - GCRobotLight (retail object name "GCRobotLigh[t]"), the
 * electric scanning-beam of CloudRunner Fortress. It is spawned as the
 * child of a GCRobotPatrol robot (the patrolling enemy run by
 * dll_00C9_enemy.c, placed in CloudRunner Fortress / fortress.romlist):
 * gcrobotlightbea_update aims a point light along a traced vector (the
 * beam) and gcrobotlightbea_hitDetect flags "player caught in the beam"
 * (hitFlags 0x80) unless playerIsDisguised - the sharp-claw disguise
 * fools it; the parent robot reads this child's hit result to react.
 * "GC" = GameCube: Rare's prefix for content reworked/added when the N64
 * "Dinosaur Planet" became the GameCube Star Fox Adventures (the GCRobot
 * family + GCbaddieShip, the GCrubble/GCpillar destructibles, and the
 * reworked GCRF_* CloudRunner Fortress sequences all carry it).
 *
 * This file is part of the sandwormBoss 10-DLL container (0x14A
 * CFPowerBase .. 0x157 SpiritDoorSpirit) covering [8019D578-801A0B14).
 * DLLs 0x148/0x149 are defined in DR/dll_0148_cfguardian.c and
 * DR/dll_0149_cfwindlift.c; their prototypes appear here.
 */
#include "main/dll/bit80_struct.h"
#include "main/game_object.h"
#include "main/obj_link.h"
#include "main/object_api.h"
#include "main/objhits.h"
#include "main/audio/sfx_ids.h"
#include "main/dll/modgfx.h"
#include "main/sky_state.h"
#include "main/model_light.h"
#include "main/dll/dll_0150_gcrobotlightbea.h"
#include "main/object_descriptor.h"

/* Per-object extra state for the robot light beacon
 * (gcrobotlightbea_getExtraSize == 0xc). */

STATIC_ASSERT(sizeof(GcRobotLightBeaState) == 0xc);

#define GCROBOTLIGHTBEA_HIT_VOLUME_SLOT 0x17

extern f32 lbl_803DBE58;
extern f32 lbl_803DBE5C;

extern void objBboxFn_800640cc(f32* p0, f32* p1, int p5, int* out, int* self, int p8, int p9, int slot, f32 f, u8 arg8);
extern void Obj_TransformLocalVectorByWorldMatrix(void* obj, f32* src, f32* dst);
extern void voxmaps_traceScaledVectorEnd(f32* dst, void* posA, f32* dir, f32 factor);
extern f32 PSVECDistance(void* a, void* b);
extern void PSVECScale(void* in, void* out, f32 scale);

#pragma scheduling off
#pragma peephole off

u32 fn_801A0174(int* obj)
{
    return (((GcRobotLightBeaState*)(int*)((GameObject*)obj)->extra)->hitFlags >> 7) & 1;
}

f32 lbl_80322C38[3] = {0.0f, -0.757f, -0.2f};

int gcrobotlightbea_getExtraSize(void)
{
    return 0xc;
}
int gcrobotlightbea_getObjectTypeId(void)
{
    return 0x0;
}

void gcrobotlightbea_free(int* obj)
{
    GcRobotLightBeaState* state = ((GameObject*)obj)->extra;
    if (state->light != NULL)
    {
        modelLightStruct_freeSlot(&state->light);
    }
    if (((GameObject*)obj)->ownerObj != NULL)
    {
        ObjLink_DetachChild((GameObject*)((GameObject*)obj)->ownerObj, (int)obj);
    }
}

void gcrobotlightbea_render(void)
{
}

/* Clear the hit flag, then re-set it only if the priority hit is the
 * (undisguised) player and lands inside the beacon's bounding box. */
void gcrobotlightbea_hitDetect(GameObject* obj)
{
    float out[22];
    f32 vec[3];
    void* hit;
    GcRobotLightBeaState* sub = (obj)->extra;
    ((Bit80*)&sub->hitFlags)->top = 0;
    if ((obj)->ownerObj == NULL)
        return;
    if (ObjHits_GetPriorityHit(obj, (int*)&hit, 0, 0) == 0)
    {
        hit = (void*)(*(ObjHitsPriorityState**)&(obj)->anim.hitReactState)->lastHitObject;
        if (hit == NULL)
            return;
    }
    if (hit != Obj_GetPlayerObject())
        return;
    if (playerIsDisguised(hit) != 0)
        return;
    vec[0] = ((ObjHitsPriorityState*)hit)->primaryRadiusSquared;
    vec[1] = 10.0f + ((ObjHitsPriorityState*)hit)->localPosX;
    vec[2] = ((ObjHitsPriorityState*)hit)->localPosY;
    if (voxmaps_traceWorldLine((void*)((char*)obj + 0xc), vec) == 0)
        return;
    if ((obj)->unkF4 != 0 || ((int (*)(int, f32*, f32, int, f32*, int, int, int, int, int))objBboxFn_800640cc)(
                                 (int)obj + 0xc, vec, 1.0f, 0, out, (int)obj, 4, -1, 0, 0) == 0)
    {
        ((Bit80*)&sub->hitFlags)->top = 1;
    }
}

void gcrobotlightbea_update(int* obj)
{
    GcRobotLightBeaState* sub;
    f32 vec[3];
    f32 vec2[3];
    u8 r_byte, g_byte, b_byte;

    sub = ((GameObject*)obj)->extra;
    if (sub->light == NULL)
    {
        sub->light = modelLightStruct_createPointLight(obj, 0xfa, 0xfa, 0xfa, 1);
        if (sub->light != NULL)
        {
            modelLightStruct_setDistanceAttenuation(sub->light, lbl_803DBE58, 12.0f + lbl_803DBE58);
        }
    }
    ObjHits_SetHitVolumeSlot((ObjAnimComponent*)obj, GCROBOTLIGHTBEA_HIT_VOLUME_SLOT, 0, 0);
    vec[0] = lbl_80322C38[0];
    vec[1] = lbl_80322C38[1];
    vec[2] = lbl_80322C38[2];
    Obj_TransformLocalVectorByWorldMatrix(obj, lbl_80322C38, vec);
    voxmaps_traceScaledVectorEnd(vec2, obj + 3, vec, lbl_803DBE5C);
    PSVECScale(lbl_80322C38, vec2, PSVECDistance((char*)obj + 0xc, vec2));
    getAmbientColor(0, &r_byte, &g_byte, &b_byte);
    if (sub->light != NULL)
    {
        ((void (*)(ModelLightStruct*, int, int, int, int))modelLightStruct_setDiffuseColor)(
            sub->light, (s32)(0.7f * (f32)(u32)r_byte), (s32)(0.7f * (f32)(u32)g_byte),
            (s32)(0.7f * (f32)(u32)b_byte), 0xff);
        modelLightStruct_setPosition(sub->light, vec2[0], vec2[1], vec2[2]);
    }
}

void gcrobotlightbea_init(int* obj)
{
    GcRobotLightBeaState* state = ((GameObject*)obj)->extra;
    state->light = NULL;
    state->unk4 = 0;
    ObjHits_EnableObject(obj);
    ((GameObject*)obj)->anim.alpha = 0x80;
}

void gcrobotlightbea_release(void)
{
}

void gcrobotlightbea_initialise(void)
{
}

ObjectDescriptor10WithPadding gGCRobotLightBeaObjDescriptor = {
    {
        0,
        0,
        0,
        OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
        (ObjectDescriptorCallback)gcrobotlightbea_initialise,
        (ObjectDescriptorCallback)gcrobotlightbea_release,
        0,
        (ObjectDescriptorCallback)gcrobotlightbea_init,
        (ObjectDescriptorCallback)gcrobotlightbea_update,
        (ObjectDescriptorCallback)gcrobotlightbea_hitDetect,
        (ObjectDescriptorCallback)gcrobotlightbea_render,
        (ObjectDescriptorCallback)gcrobotlightbea_free,
        (ObjectDescriptorCallback)gcrobotlightbea_getObjectTypeId,
        gcrobotlightbea_getExtraSize,
    },
    0,
};
