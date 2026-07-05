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
#include "main/obj_placement.h"
#include "main/objtexture.h"
#include "main/mm.h"
#include "main/dll/VF/vf_shared.h"
extern void getTabEntry(void* dst, int kind, int offset, int size);
extern void ObjModel_SetBlendChannelTargets(int* model, int channel, int p3, int p4, f32 weight, int p6);
extern void ObjModel_SetBlendChannelWeight(int* model, int channel, f32 weight);
extern s16 gImSpaceThrusterKeyframeIndexA[], gImSpaceThrusterKeyframeIndexB[];
extern f32 gImSpaceThrusterWeightMax;
extern f32 gImSpaceThrusterRootMotionScaleKind01, gImSpaceThrusterRootMotionScaleKind23, gImSpaceThrusterRootMotionScaleKind56, gImSpaceThrusterRootMotionScaleKind4;
extern f32 lbl_803E478C, lbl_803E4790, gImSpaceThrusterAlphaToWeightScale, lbl_803E4798;

typedef enum ImSpaceThrusterPhase
{
    IMSPACETHRUSTER_PHASE_OFF = 0,
    IMSPACETHRUSTER_PHASE_ON = 1,
    IMSPACETHRUSTER_PHASE_FADE_OUT = 2,
} ImSpaceThrusterPhase;

/* Class-specific placement record: ObjPlacement common head (0x00..0x17)
 * followed by this thruster's setup fields. */
typedef struct ImSpaceThrusterPlacement
{
    ObjPlacement head;
    s8 rotXByte;  /* 0x18: high byte of the spawn rotX */
    u8 kind;      /* 0x19: thruster kind 0..6 */
    s16 rotY;     /* 0x1a */
    s16 bankIndex; /* 0x1c */
} ImSpaceThrusterPlacement;

STATIC_ASSERT(offsetof(ImSpaceThrusterPlacement, rotXByte) == 0x18);
STATIC_ASSERT(offsetof(ImSpaceThrusterPlacement, rotY) == 0x1a);
STATIC_ASSERT(offsetof(ImSpaceThrusterPlacement, bankIndex) == 0x1c);

static inline int* getActiveModel(void* obj)
{
    ObjAnimComponent* objAnim = (ObjAnimComponent*)obj;
    return (int*)objAnim->banks[objAnim->bankIndex];
}

int imspacethruster_getExtraSize(void) { return 0xc; }
int imspacethruster_getObjectTypeId(void) { return 0x0; }

void imspacethruster_free(int obj)
{
    ImSpaceThrusterState* state = ((GameObject*)obj)->extra;
    if (state->bufA != 0) mm_free(state->bufA);
    if (state->bufB != 0) mm_free(state->bufB);
}

void imspacethruster_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0) objRenderFn_8003b8f4(p1, p2, p3, p4, p5, gImSpaceThrusterWeightMax);
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
        mode = (*(s16 (**)(int, int))(*(int*)(*(int*)&((GameObject*)obj->anim.parent)->anim.dll) + 0x20))(
            *(int*)&obj->anim.parent, state->kind);
        switch (state->phase)
        {
        case IMSPACETHRUSTER_PHASE_OFF:
            if (mode == 1)
            {
                ObjModel_SetBlendChannelTargets(getActiveModel(obj), 0, -1, 0, lbl_803E478C, 0x10);
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
                ObjModel_SetBlendChannelTargets(getActiveModel(obj), 0, -1, 0, lbl_803E4790, 0x10);
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
            f32 weight = obj->anim.alpha / gImSpaceThrusterAlphaToWeightScale;
            if (weight > gImSpaceThrusterWeightMax)
            {
                weight = gImSpaceThrusterWeightMax;
            }
            else if (weight < lbl_803E4798)
            {
                weight = lbl_803E4798;
            }
            ((void (*)(int, f32, int))((void**)*(void**)*(int*)(*(int*)&obj->anim.parent + 0x68))[10])(
                *(int*)&obj->anim.parent, weight, state->kind);
        }
        tex = objFindTexture(obj, 0, 0);
        scroll = -tex->offsetT;
        scroll += 0x100;
        if (scroll > 0x800)
        {
            scroll -= 0x800;
        }
        tex->offsetT = -scroll;
        tex = objFindTexture(obj, 1, 0);
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
    int* model;

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
    ObjModel_SetBlendChannelTargets(model, 0, -1, 0, lbl_803E4798, 0);
    ObjModel_SetBlendChannelWeight(model, 0, gImSpaceThrusterWeightMax);
    {
        u32 kind = state->kind;
        if (kind < 5)
        {
            state->bufA = mmAlloc(0x28, 0x12, 0);
            getTabEntry(state->bufA, 0xc, gImSpaceThrusterKeyframeIndexA[kind] * 0x28, 0x28);
            state->bufB = mmAlloc(0x28, 0x12, 0);
            getTabEntry(state->bufB, 0xc, gImSpaceThrusterKeyframeIndexB[kind] * 0x28, 0x28);
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
