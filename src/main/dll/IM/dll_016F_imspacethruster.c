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
#include "main/objtexture.h"
#include "main/mm.h"
#include "main/dll/VF/vf_shared.h"


extern void getTabEntry(void* dst, int kind, int offset, int size);


extern u8 framesThisStep;
extern void ObjModel_SetBlendChannelTargets(int* model, int channel, int p3, int p4, f32 weight, int p6);
extern void ObjModel_SetBlendChannelWeight(int* model, int channel, f32 weight);

extern s16 lbl_80323818[], lbl_80323824[];

extern f32 lbl_803E4788;
extern f32 lbl_803E47A8, lbl_803E47AC, lbl_803E47B0, lbl_803E47B4;
extern f32 lbl_803E478C, lbl_803E4790, lbl_803E4794, lbl_803E4798;

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
    if (v != 0) objRenderFn_8003b8f4(lbl_803E4788);
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
        mode = ((s16 (*)(int, int))((void**)*(void**)*(int*)(*(int*)&obj->anim.parent + 0x68))[8])(
            *(int*)&obj->anim.parent, state->kind);
        switch (state->phase)
        {
        case 0:
            if (mode == 1)
            {
                ObjModel_SetBlendChannelTargets(getActiveModel(obj), 0, -1, 0, lbl_803E478C, 0x10);
                obj->anim.alpha = 0xff;
                state->phase = 1;
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
        case 1:
            if (mode == 0)
            {
                ObjModel_SetBlendChannelTargets(getActiveModel(obj), 0, -1, 0, lbl_803E4790, 0x10);
                state->blendTimer = 0xb4;
                obj->anim.alpha = 0xa4;
                state->phase = 2;
            }
            break;
        case 2:
            if (mode == 1)
            {
                state->phase = 1;
            }
            else
            {
                if ((state->blendTimer -= framesThisStep) < 0)
                {
                    state->phase = 0;
                }
            }
            break;
        }
        if (state->kind < 5)
        {
            f32 weight = obj->anim.alpha / lbl_803E4794;
            if (weight > lbl_803E4788)
            {
                weight = lbl_803E4788;
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
    int* model;

    obj->anim.rotX = (s16)((s8)placement[0x18] << 8);
    obj->anim.rotY = *(s16*)((char*)placement + 0x1a);
    objAnim->bankIndex = (s8) * (s16*)((char*)placement + 0x1c);
    state->kind = placement[0x19];
    switch (state->kind)
    {
    case 0:
    case 1:
        obj->anim.rootMotionScale = lbl_803E47A8;
        break;
    case 2:
    case 3:
        obj->anim.rootMotionScale = lbl_803E47AC;
        break;
    case 5:
    case 6:
        obj->anim.rootMotionScale = lbl_803E47B0;
        break;
    case 4:
        obj->anim.rootMotionScale = lbl_803E47B4;
        break;
    }
    model = getActiveModel(obj);
    ObjModel_SetBlendChannelTargets(model, 0, -1, 0, lbl_803E4798, 0);
    ObjModel_SetBlendChannelWeight(model, 0, lbl_803E4788);
    {
        u32 kind = state->kind;
        if (kind < 5)
        {
            *(int*)&state->bufA = (int)mmAlloc(0x28, 0x12, 0);
            getTabEntry(state->bufA, 0xc, lbl_80323818[kind] * 0x28, 0x28);
            *(int*)&state->bufB = (int)mmAlloc(0x28, 0x12, 0);
            getTabEntry(state->bufB, 0xc, lbl_80323824[kind] * 0x28, 0x28);
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
