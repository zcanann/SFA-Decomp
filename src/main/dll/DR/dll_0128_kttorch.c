/*
 * kttorch (DLL 0x128) - the lit torches / braziers dressing the
 * KrazoaPalace and ThornTail areas.
 *
 * init sizes the flame from the placement's scale byte (clamped to a
 * floor), seeds the swaying rotation, picks the model bank and start
 * move, and makes the torch visible only while its placement game bit
 * is set. update advances the flame animation each frame and keeps the
 * visibility in sync with the game bit. The torch has no extra state of
 * its own (getExtraSize == 0); all parameters come from the placement.
 */
#include "main/game_object.h"
#include "main/gamebits.h"
#include "main/dll/VF/vf_shared.h"
extern f32 lbl_803E3DB0;
extern f32 lbl_803E3DB4;
extern f32 lbl_803E3DC0;
extern f32 lbl_803E3DC4;
extern f32 lbl_803E3DC8;

typedef struct KtTorchPlacement
{
    u8 pad0[0x18 - 0x0];
    u8 modelBankIndex;     /* 0x18: model bank, clamped to modelCount */
    u8 startMove;          /* 0x19: initial anim move index */
    u8 moveStartSpeed;     /* 0x1A: initial move speed factor */
    u8 animSpeed;          /* 0x1B */
    u8 flameScale;         /* 0x1C: flame scale byte, clamped to a floor */
    u8 swayRotPacked;      /* 0x1D: low 6 bits seed the swaying rotation */
    u8 pad1E[0x20 - 0x1E];
    s16 visGameBit;        /* 0x20: -1 disables, else gates visibility */
} KtTorchPlacement;

STATIC_ASSERT(offsetof(KtTorchPlacement, animSpeed) == 0x1B);
STATIC_ASSERT(offsetof(KtTorchPlacement, visGameBit) == 0x20);
STATIC_ASSERT(sizeof(KtTorchPlacement) == 0x22);

void kt_torch_init(int obj, int placement)
{
    ObjAnimComponent* objAnim = (ObjAnimComponent*)obj;
    f32 scale;
    u8 scaleByte;

    ((GameObject*)obj)->anim.flags |= 2;
    scaleByte = ((KtTorchPlacement*)placement)->flameScale;
    scale = (f32)(int)scaleByte;
    if ((f32)(int)scaleByte < lbl_803E3DC0)
    {
        scale = *(f32*)&lbl_803E3DC0;
    }
    scale *= lbl_803E3DC4;
    ((GameObject*)obj)->anim.rootMotionScale = ((GameObject*)obj)->anim.modelInstance->rootMotionScaleBase * scale;
    ((GameObject*)obj)->anim.rotX = (s16)((((KtTorchPlacement*)placement)->swayRotPacked & 0x3f) << 10);
    if (((GameObject*)obj)->anim.modelState != NULL)
    {
        **(f32**)&((GameObject*)obj)->anim.modelState = **(f32**)&((GameObject*)obj)->anim.modelInstance * scale;
    }
    objAnim->bankIndex = (s8)((KtTorchPlacement*)placement)->modelBankIndex;
    if (objAnim->bankIndex >= objAnim->modelInstance->modelCount)
    {
        objAnim->bankIndex = 0;
    }
    ObjAnim_SetCurrentMove(obj, ((KtTorchPlacement*)placement)->startMove,
                           (f32)((KtTorchPlacement*)placement)->moveStartSpeed * lbl_803E3DC8, 0);
    {
        s16 visBit = ((KtTorchPlacement*)placement)->visGameBit;
        if (visBit != -1)
        {
            if (GameBit_Get(visBit) != 0)
            {
                ((GameObject*)obj)->anim.alpha = 0xff;
            }
            else
            {
                ((GameObject*)obj)->anim.alpha = 0;
            }
        }
    }
}

void kt_torch_free(void)
{
}

void kt_torch_hitDetect(void)
{
}

void kt_torch_release(void)
{
}

void kt_torch_initialise(void)
{
}

void kt_torch_update(int obj)
{
    int placement;
    int visBit;

    placement = *(int*)&((GameObject*)obj)->anim.placementData;
    ObjAnim_AdvanceCurrentMove((f32)((KtTorchPlacement*)placement)->animSpeed / lbl_803E3DB4,
                               timeDelta, obj, (ObjAnimEventList*)0);
    visBit = ((KtTorchPlacement*)placement)->visGameBit;
    if (visBit != -1)
    {
        if (GameBit_Get(visBit) != 0)
        {
            ((GameObject*)obj)->anim.alpha = 0xff;
        }
        else
        {
            ((GameObject*)obj)->anim.alpha = 0;
        }
    }
}

int kt_torch_getExtraSize(void) { return 0x0; }
int kt_torch_getObjectTypeId(void) { return 0x0; }

void kt_torch_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0) objRenderFn_8003b8f4(lbl_803E3DB0);
}
