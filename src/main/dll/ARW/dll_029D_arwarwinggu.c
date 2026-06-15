#include "main/dll/dll_80220608_shared.h"
#include "main/game_object.h"

typedef struct ArwingGuTextureState
{
    u8 textureAnim[4];
    int textureFrame;
} ArwingGuTextureState;

typedef union ArwingGuState
{
    ArwingGuTextureState texture;
    f32 visibleTimer;
    u8 fadeIn;
} ArwingGuState;

STATIC_ASSERT(sizeof(ArwingGuTextureState) == 0x8);
STATIC_ASSERT(offsetof(ArwingGuTextureState, textureFrame) == 0x04);
STATIC_ASSERT(sizeof(ArwingGuState) == 0x8);

int arwarwinggu_getExtraSize(int obj)
{
    switch (((GameObject*)obj)->anim.seqId)
    {
    case 0x606:
        return 8;
    case 0x610:
    case 0x615:
        return 4;
    case 0x611:
        return 1;
    default:
        return 0;
    }
}

int arwarwinggu_getObjectTypeId(void) { return 0; }

void arwarwinggu_free(void)
{
}

void arwarwinggu_render(void)
{
}

void arwarwinggu_hitDetect(void)
{
}

#pragma peephole off
#pragma scheduling off
void arwarwinggu_init(int obj)
{
    ObjAnimComponent* objAnim = &((GameObject*)obj)->anim;

    if (((GameObject*)obj)->anim.seqId == 0x606)
    {
        return;
    }
    objAnim->flags |= OBJANIM_FLAG_HIDDEN;
    objAnim->alpha = 0;
}
#pragma scheduling reset
#pragma peephole reset

#pragma scheduling off
#pragma peephole off
void arwarwinggu_setActiveVisible(int obj, u8 active, u8 visible)
{
    ObjAnimComponent* objAnim = &((GameObject*)obj)->anim;
    ArwingGuState* state = ((GameObject*)obj)->extra;

    if (active != 0)
    {
        Obj_SetActiveModelIndex(obj, visible != 0 ? 1 : 0);
        ((GameObject*)obj)->anim.flags &= ~OBJANIM_FLAG_HIDDEN;
        objAnim->alpha = 0xff;
        state->visibleTimer = lbl_803E7058;
    }
    else
    {
        ((GameObject*)obj)->anim.flags |= OBJANIM_FLAG_HIDDEN;
        objAnim->alpha = 0;
    }
}

#pragma scheduling on
#pragma peephole on
void arwarwinggu_release(void)
{
}

void arwarwinggu_initialise(void)
{
}

#pragma scheduling off
#pragma peephole off
void arwarwinggu_update(int obj)
{
    ObjAnimComponent* objAnim = &((GameObject*)obj)->anim;

    switch (((GameObject*)obj)->anim.seqId)
    {
    case 0x606:
        {
            ArwingGuState* state = ((GameObject*)obj)->extra;
            int model = Obj_GetActiveModel(obj);
            ObjTextureRuntimeSlot* texture = objFindTexture((void*)obj, 0, 0);
            int anim = ObjModel_GetTexture(*(int*)model, 0);
            fn_800541A4(anim, (u16)state->texture.textureFrame);
            textureAnimFn_80053f2c(anim, (int)state, (int)texture);
            break;
        }
    case 0x610:
    case 0x615:
        {
            ArwingGuState* state = ((GameObject*)obj)->extra;
            f32 limit;
            if (state->visibleTimer > (limit = lbl_803E7060))
            {
                state->visibleTimer -= timeDelta;
                if (state->visibleTimer <= limit)
                {
                    state->visibleTimer = limit;
                    objAnim->alpha = 0;
                }
            }
            break;
        }
    case 0x611:
        {
            ArwingGuState* state = ((GameObject*)obj)->extra;
            f32 v;
            if (state->fadeIn != 0)
            {
                v = lbl_803E705C * timeDelta + (f32)(u32)
                objAnim->alpha;
            }
            else
            {
                v = (f32)(u32)
                objAnim->alpha - lbl_803E705C * timeDelta;
            }
            if (v < lbl_803E7060)
            {
                v = lbl_803E7060;
            }
            else if (v > lbl_803E705C)
            {
                v = lbl_803E705C;
            }
            objAnim->alpha = v;
            break;
        }
    }
}

#pragma scheduling on
#pragma peephole on
void fn_8022F270(int obj, int p2)
{
    ArwingGuState* state = ((GameObject*)obj)->extra;
    state->texture.textureFrame = p2;
}

#pragma scheduling off
#pragma peephole off
void fn_8022F27C(int obj)
{
    ArwingGuState* state = ((GameObject*)obj)->extra;
    int model = Obj_GetActiveModel(obj);
    ObjTextureRuntimeSlot* texture = objFindTexture((void*)obj, 0, 0);
    int anim = ObjModel_GetTexture(*(int*)model, 0);
    fn_800541A4(anim, (u16)state->texture.textureFrame);
    textureAnimFn_80053f2c(anim, (int)state, (int)texture);
}
