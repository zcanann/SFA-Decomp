/*
 * imspacethruster (DLL 0x16F) - an engine exhaust attached to the
 * SpaceCraft cinematic object on the Ice Mountain map.
 *
 * init picks a thruster "kind" (0..6) from the placement, selecting a
 * root-motion scale and, for the animated kinds (<5), loading two
 * blend-channel keyframe tables from the tab file. update runs a small
 * three-phase fade machine driven by the parent's query result, pushes
 * a thrust weight back to the parent, and scrolls the exhaust textures.
 */
#include "main/dll/imspacethrusterstate_struct.h"
#include "main/game_object.h"
#include "main/model.h"
#include "main/asset_load.h"
#include "main/obj_placement.h"
#include "main/objtexture.h"
#include "main/mm.h"
#include "main/pi_dolphin.h"
#include "main/frame_timing.h"
#include "main/object_render_legacy.h"
#include "main/dll/IM/dll_016F_imspacethruster.h"
#include "main/object_descriptor.h"

#pragma force_active on
#define IM_SPACE_THRUSTER_WEIGHT_MAX 1.0f
#define IM_SPACE_THRUSTER_ALPHA_TO_WEIGHT_SCALE 255.0f
#pragma force_active reset

s16 gImSpaceThrusterKeyframeIndexA[6] = {0x160, 0x161, 0x162, 0x163, 0x165, 0};
s16 gImSpaceThrusterKeyframeIndexB[6] = {3, 4, 5, 6, 7, 0};
extern f32 gImSpaceThrusterRootMotionScaleKind01;
extern f32 gImSpaceThrusterRootMotionScaleKind23;
extern f32 gImSpaceThrusterRootMotionScaleKind56;
extern f32 gImSpaceThrusterRootMotionScaleKind4;
static inline ObjModel* getActiveModel(void* obj)
{
    ObjAnimComponent* objAnim = (ObjAnimComponent*)obj;
    return (ObjModel*)objAnim->banks[objAnim->bankIndex];
}

int imspacethruster_getExtraSize(void)
{
    return 0xc;
}
int imspacethruster_getObjectTypeId(void)
{
    return 0x0;
}

void imspacethruster_free(GameObject* obj)
{
    ImSpaceThrusterState* state = obj->extra;
    if (state->bufA != 0)
        mm_free(state->bufA);
    if (state->bufB != 0)
        mm_free(state->bufB);
}

void imspacethruster_render(int obj, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0)
        objRenderModelAndHitVolumes(obj, p2, p3, p4, p5, IM_SPACE_THRUSTER_WEIGHT_MAX);
}

void imspacethruster_hitDetect(void)
{
}

void imspacethruster_update(GameObject* obj)
{
    ImSpaceThrusterState* state;
    int mode;
    s16 scroll;
    ObjTextureRuntimeSlot* tex;

    state = obj->extra;
    if (obj->anim.parent != NULL)
    {
        mode = (*(s16(**)(int, int))(*(int*)(*(int*)&((GameObject*)obj->anim.parent)->anim.dll) + 0x20))(
            *(int*)&obj->anim.parent, state->kind);
        switch (state->phase)
        {
        case IMSPACETHRUSTER_PHASE_OFF:
            if (mode == 1)
            {
                ObjModel_SetBlendChannelTargets(getActiveModel(obj), 0, -1, 0, -0.2f, 0x10);
                obj->anim.alpha = 0xff;
                state->phase = IMSPACETHRUSTER_PHASE_ON;
            }
            else
            {
                int d = obj->anim.alpha - framesThisStep * 8;
                if (d < 0)
                {
                    d = 0;
                }
                obj->anim.alpha = d;
            }
            break;
        case IMSPACETHRUSTER_PHASE_ON:
            if (mode == 0)
            {
                ObjModel_SetBlendChannelTargets(getActiveModel(obj), 0, -1, 0, 0.2f, 0x10);
                state->blendTimer = 0xb4;
                obj->anim.alpha = 0xa4;
                state->phase = IMSPACETHRUSTER_PHASE_FADE_OUT;
            }
            break;
        case IMSPACETHRUSTER_PHASE_FADE_OUT:
            if (mode == 1)
            {
                state->phase = IMSPACETHRUSTER_PHASE_ON;
            }
            else
            {
                if ((state->blendTimer -= framesThisStep) < 0)
                {
                    state->phase = IMSPACETHRUSTER_PHASE_OFF;
                }
            }
            break;
        }
        if (state->kind < 5)
        {
            f32 weight = obj->anim.alpha / IM_SPACE_THRUSTER_ALPHA_TO_WEIGHT_SCALE;
            if (weight > IM_SPACE_THRUSTER_WEIGHT_MAX)
            {
                weight = IM_SPACE_THRUSTER_WEIGHT_MAX;
            }
            else if (weight < 0.0f)
            {
                weight = 0.0f;
            }
            ((void (*)(int, f32, int))((void**)*(void**)*(int*)(*(int*)&obj->anim.parent + 0x68))[10])(
                *(int*)&obj->anim.parent, weight, state->kind);
        }
        tex = objFindTexture((GameObject*)(obj), 0, 0);
        scroll = -tex->offsetT;
        scroll += 0x100;
        if (scroll > 0x800)
        {
            scroll -= 0x800;
        }
        tex->offsetT = -scroll;
        tex = objFindTexture((GameObject*)(obj), 1, 0);
        scroll = -tex->offsetT;
        scroll += 0xa0;
        if (scroll > 0x800)
        {
            scroll -= 0x800;
        }
        tex->offsetT = -scroll;
    }
}

void imspacethruster_init(GameObject* obj, u8* placement)
{
    ObjAnimComponent* objAnim = (ObjAnimComponent*)obj;
    ImSpaceThrusterState* state = obj->extra;
    ImSpaceThrusterPlacement* p = (ImSpaceThrusterPlacement*)placement;
    ObjModel* model;

    obj->anim.rotX = (s16)(p->rotXByte << 8);
    obj->anim.rotY = p->rotY;
    objAnim->bankIndex = (s8)p->bankIndex;
    state->kind = p->kind;
    switch (state->kind)
    {
    case 0:
    case 1:
        obj->anim.rootMotionScale = gImSpaceThrusterRootMotionScaleKind01;
        break;
    case 2:
    case 3:
        obj->anim.rootMotionScale = gImSpaceThrusterRootMotionScaleKind23;
        break;
    case 5:
    case 6:
        obj->anim.rootMotionScale = gImSpaceThrusterRootMotionScaleKind56;
        break;
    case 4:
        obj->anim.rootMotionScale = gImSpaceThrusterRootMotionScaleKind4;
        break;
    }
    model = getActiveModel(obj);
    ObjModel_SetBlendChannelTargets(model, 0, -1, 0, 0.0f, 0);
    ObjModel_SetBlendChannelWeight(model, 0, IM_SPACE_THRUSTER_WEIGHT_MAX);
    {
        u32 kind = state->kind;
        if (kind < 5)
        {
            state->bufA = mmAlloc(0x28, 0x12, 0);
            getTabEntry(state->bufA, MLDF_FILEID_LACTIONS_BIN, gImSpaceThrusterKeyframeIndexA[kind] * 0x28, 0x28);
            state->bufB = mmAlloc(0x28, 0x12, 0);
            getTabEntry(state->bufB, MLDF_FILEID_LACTIONS_BIN, gImSpaceThrusterKeyframeIndexB[kind] * 0x28, 0x28);
        }
    }
    obj->anim.alpha = 0;
}

void imspacethruster_release(void)
{
}

void imspacethruster_initialise(void)
{
}

ObjectDescriptor gIMSpaceThrusterObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)imspacethruster_initialise,
    (ObjectDescriptorCallback)imspacethruster_release,
    0,
    (ObjectDescriptorCallback)imspacethruster_init,
    (ObjectDescriptorCallback)imspacethruster_update,
    (ObjectDescriptorCallback)imspacethruster_hitDetect,
    (ObjectDescriptorCallback)imspacethruster_render,
    (ObjectDescriptorCallback)imspacethruster_free,
    (ObjectDescriptorCallback)imspacethruster_getObjectTypeId,
    imspacethruster_getExtraSize,
};
