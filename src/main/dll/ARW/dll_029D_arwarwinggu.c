/*
 * arwarwinggu (DLL 0x29D) - the Arwing's attached "gear" models in the
 * on-rails flight sections: the twin laser guns (def 0x610 / 0x615), the
 * bomb model (def 0x611) and the engine/escort model (def 0x606). One DLL
 * drives all of them, branching on the object's seqId. getExtraSize and
 * update therefore return / interpret a different state shape per seqId:
 *   0x606  engine - scrolls a texture animation (8-byte texture state)
 *   0x610/0x615 guns - count down a "just fired" visible timer, then hide
 *   0x611  bomb - fades alpha in or out toward a target (1-byte fadeIn flag)
 * arwarwinggu_setActiveVisible shows/hides a gun and selects its model
 * index; the arwarwing TU calls it when a shot is fired.
 */
#include "main/dll/dll_80220608_shared.h"
#include "main/dll/ARW/dll_029D_arwarwinggu.h"
#include "main/game_object.h"
#include "main/object_api.h"

/* object def numbers (== seqId) of the Arwing's attached models */
enum
{
    ARWGU_DEF_ENGINE = 0x606, /* escort / engine, animated texture */
    ARWGU_DEF_GUN_L = 0x610,
    ARWGU_DEF_BOMB = 0x611,
    ARWGU_DEF_GUN_R = 0x615
};

#pragma scheduling off
#pragma peephole off
void arwarwinggu_setActiveVisible(GameObject* obj, u8 active, u8 visible)
{
    ObjAnimComponent* objAnim = &(obj)->anim;
    ArwingGuState* state = (obj)->extra;

    if (active != 0)
    {
        Obj_SetActiveModelIndex(obj, visible != 0 ? 1 : 0);
        (obj)->anim.flags &= ~OBJANIM_FLAG_HIDDEN;
        objAnim->alpha = 0xff;
        state->visibleTimer = lbl_803E7058;
    }
    else
    {
        (obj)->anim.flags |= OBJANIM_FLAG_HIDDEN;
        objAnim->alpha = 0;
    }
}

#pragma scheduling on
#pragma peephole on
void arwarwinggu_setTextureFrame(GameObject* obj, int textureFrame)
{
    ArwingGuState* state = obj->extra;
    state->texture.textureFrame = textureFrame;
}

#pragma scheduling off
#pragma peephole off
void arwarwinggu_applyTextureFrame(GameObject* obj)
{
    int model;
    ObjTextureRuntimeSlot* texture;
    ArwingGuState* state = (obj)->extra;
    int anim;
    model = Obj_GetActiveModel((int)obj);
    texture = objFindTexture(obj, 0, 0);
    anim = ObjModel_GetTexture(*(int*)model, 0);
    fn_800541A4(anim, (u16)state->texture.textureFrame);
    textureAnimFn_80053f2c(anim, (int)state, (int)texture);
}
#pragma scheduling on
#pragma peephole on

int ARWArwingGu_getExtraSize(GameObject* obj)
{
    switch (obj->anim.seqId)
    {
    case ARWGU_DEF_ENGINE:
        return 8;
    case ARWGU_DEF_GUN_L:
    case ARWGU_DEF_GUN_R:
        return 4;
    case ARWGU_DEF_BOMB:
        return 1;
    default:
        return 0;
    }
}

int ARWArwingGu_getObjectTypeId(void)
{
    return 0;
}

void ARWArwingGu_free(void)
{
}

void ARWArwingGu_render(void)
{
}

void ARWArwingGu_hitDetect(void)
{
}

#pragma scheduling off
#pragma peephole off
void ARWArwingGu_update(GameObject* obj)
{
    ObjAnimComponent* objAnim = &(obj)->anim;

    switch ((obj)->anim.seqId)
    {
    case ARWGU_DEF_ENGINE:
    {
        ArwingGuState* state = (obj)->extra;
        int model = Obj_GetActiveModel((int)obj);
        ObjTextureRuntimeSlot* texture = objFindTexture(obj, 0, 0);
        int anim = ObjModel_GetTexture(*(int*)model, 0);
        fn_800541A4(anim, (u16)state->texture.textureFrame);
        textureAnimFn_80053f2c(anim, (int)state, (int)texture);
        break;
    }
    case ARWGU_DEF_GUN_L:
    case ARWGU_DEF_GUN_R:
    {
        ArwingGuState* state = (obj)->extra;
        f32 minTimer;
        f32 vt = state->visibleTimer;
        if (vt > (minTimer = lbl_803E7060))
        {
            state->visibleTimer = vt - timeDelta;
            if (state->visibleTimer <= minTimer)
            {
                state->visibleTimer = minTimer;
                objAnim->alpha = 0;
            }
        }
        break;
    }
    case ARWGU_DEF_BOMB:
    {
        ArwingGuState* state = (obj)->extra;
        f32 alpha;
        if (state->fadeIn != 0)
        {
            alpha = lbl_803E705C * timeDelta + (f32)(u32)objAnim->alpha;
        }
        else
        {
            alpha = (f32)(u32)objAnim->alpha - lbl_803E705C * timeDelta;
        }
        if (alpha < lbl_803E7060)
        {
            alpha = lbl_803E7060;
        }
        else if (alpha > lbl_803E705C)
        {
            alpha = lbl_803E705C;
        }
        objAnim->alpha = alpha;
        break;
    }
    }
}

void ARWArwingGu_init(GameObject* obj)
{
    if (obj->anim.seqId == ARWGU_DEF_ENGINE)
    {
        return;
    }
    obj->anim.flags |= OBJANIM_FLAG_HIDDEN;
    obj->anim.alpha = 0;
}

void ARWArwingGu_release(void)
{
}

void ARWArwingGu_initialise(void)
{
}
