#include "main/game_object.h"

extern f32 lbl_803E3D60;
extern void objRenderFn_8003b8f4(f32);
extern u8 framesThisStep;
extern f32 lbl_803E3D64;
extern f32 lbl_803E3D68;

void dll_127_free_nop(void)
{
}

void dll_127_hitDetect_nop(void)
{
}

int fuelcell_getExtraSize(void);
int dll_127_getExtraSize_ret_0(void) { return 0x0; }
int dll_127_getObjectTypeId(void) { return 0x13; }

void dll_127_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0) objRenderFn_8003b8f4(lbl_803E3D60);
}

void dll_127_update(int obj)
{
    int flags;
    ObjHitsPriorityState* hitState;

    if (((GameObject*)obj)->anim.hitReactState == 0)
    {
        return;
    }
    if (*(short*)(obj + 0xf8) > 0)
    {
        *(short*)(obj + 0xf8) -= framesThisStep;
    }
    hitState = (ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState;
    flags = hitState->flags & 8;
    if (flags == 0)
    {
        return;
    }
    if (*(short*)(obj + 0xf8) > 0)
    {
        return;
    }
    *(short*)(obj + 0xf8) = 100;
}

void dll_127_init(short* obj, int def)
{
    ObjAnimComponent* objAnim;
    float scale;
    uint yawBits;
    u8 swayMag;

    objAnim = (ObjAnimComponent*)obj;
    obj[3] = obj[3] | 2;
    swayMag = *(u8*)(def + 0x19);
    scale = (f32)(int)
    swayMag;
    if ((f32)(int)swayMag < lbl_803E3D64
    )
    {
        scale = *(f32*)&lbl_803E3D64;
    }
    scale = scale * lbl_803E3D68;
    *(float*)(obj + 4) = *(float*)(*(int*)(obj + 0x28) + 4) * scale;
    if (*(float**)(obj + 0x32) != (float*)0x0)
    {
        **(float**)(obj + 0x32) = **(float**)(obj + 0x28) * scale;
    }
    objAnim->bankIndex = (s8) * (u8*)(def + 0x18);
    yawBits = *(byte*)(def + 0x1a) & 0x3f;
    *obj = (short)(yawBits << 10);
    if (objAnim->bankIndex >= objAnim->modelInstance->modelCount)
    {
        objAnim->bankIndex = 0;
    }
    *(undefined4*)(obj + 0x7a) = 0;
    *(undefined4*)(obj + 0x7c) = 0;
    return;
}

void dll_127_release_nop(void)
{
}

void dll_127_initialise_nop(void)
{
}
