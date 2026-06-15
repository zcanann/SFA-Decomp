/* DLL 0x128 — KT torch / campfire objects [8018CD64-8018CDAC) */
#include "main/game_object.h"

extern uint GameBit_Get(int eventId);

extern void objRenderFn_8003b8f4(f32);

extern f32 timeDelta;


typedef struct KtTorchPlacement
{
    u8 pad0[0x1B - 0x0];
    u8 unk1B;
    u8 pad1C[0x20 - 0x1C];
} KtTorchPlacement;

extern u32 GameBit_Get(int bit);

extern f32 lbl_803E3DB0;
extern f32 lbl_803E3DB4;

extern f32 lbl_803E3DC0;
extern f32 lbl_803E3DC4;
extern f32 lbl_803E3DC8;

void kt_torch_init(int obj, int p2)
{
    ObjAnimComponent* objAnim = (ObjAnimComponent*)obj;
    f32 scale;
    u8 b;

    ((GameObject*)obj)->anim.flags |= 2;
    b = *(u8*)(p2 + 0x1c);
    scale = (f32)(int)
    b;
    if ((f32)(int)b < lbl_803E3DC0
    )
    {
        scale = *(f32*)&lbl_803E3DC0;
    }
    scale *= lbl_803E3DC4;
    ((GameObject*)obj)->anim.rootMotionScale = ((GameObject*)obj)->anim.modelInstance->rootMotionScaleBase * scale;
    *(s16*)obj = (s16)((*(u8*)(p2 + 0x1d) & 0x3f) << 10);
    if (((GameObject*)obj)->anim.modelState != NULL)
    {
        **(f32**)&((GameObject*)obj)->anim.modelState = **(f32**)&((GameObject*)obj)->anim.modelInstance * scale;
    }
    objAnim->bankIndex = (s8) * (u8*)(p2 + 0x18);
    if (objAnim->bankIndex >= objAnim->modelInstance->modelCount)
    {
        objAnim->bankIndex = 0;
    }
    ObjAnim_SetCurrentMove(obj, *(u8*)(p2 + 0x19), (f32) * (u8*)(p2 + 0x1a) * lbl_803E3DC8, 0);
    {
        s16 bit = *(s16*)(p2 + 0x20);
        if (bit != -1)
        {
            if (GameBit_Get(bit) != 0)
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

void campfire_free(int obj);

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
    int mapData;
    int bit;

    mapData = *(int*)&((GameObject*)obj)->anim.placementData;
    ObjAnim_AdvanceCurrentMove((f32)((KtTorchPlacement*)mapData)->unk1B / lbl_803E3DB4,
                               timeDelta, obj, (ObjAnimEventList*)0);
    bit = *(short*)(mapData + 0x20);
    if (bit != -1)
    {
        if (GameBit_Get(bit) != 0)
        {
            ((GameObject*)obj)->anim.alpha = 0xff;
        }
        else
        {
            ((GameObject*)obj)->anim.alpha = 0;
        }
    }
}

int campfire_getExtraSize(void);
int kt_torch_getExtraSize(void) { return 0x0; }
int kt_torch_getObjectTypeId(void) { return 0x0; }

void kt_torch_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0) objRenderFn_8003b8f4(lbl_803E3DB0);
}
