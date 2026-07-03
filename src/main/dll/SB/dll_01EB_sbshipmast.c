/*
 * sbshipmast (DLL 0x1EB) - the mast/rigging attachment of the SB Galleon
 * boss ship. It rides its parent galleon object, pinning its local position
 * to the origin every frame, and picks one of three animation play speeds
 * depending on the galleon's animation type (anim.seqId 0x139) and its
 * unkF4 phase counter. The remaining handlers (free/hitDetect/init/release/
 * initialise) are stubs - the mast is purely cosmetic.
 */
#include "main/dll/sbshipheadstate_struct.h"
#include "main/dll/sbpropellerstate_struct.h"
#include "main/dll/DB/DBstealerworm.h"
#include "main/dll/VF/vf_shared.h"

STATIC_ASSERT(sizeof(SBPropellerState) == 0x10);

STATIC_ASSERT(sizeof(SBShipHeadState) == 0x10);

/* parent galleon anim.seqId selecting the rigging-animation behavior */
#define SB_GALLEON_SEQID 0x139

extern const f32 lbl_803E586C; /* 0.0f: pins localPos to the origin */
extern f32 lbl_803E5870;       /* fast play speed (phase >= 0xc) */
extern f32 lbl_803E5874;       /* medium play speed (0xa <= phase < 0xc) */
extern f32 lbl_803E5878;       /* idle play speed */
extern f32 lbl_803E5868;

void SB_ShipMast_free(void)
{
}

void SB_ShipMast_hitDetect(void)
{
}

void SB_ShipMast_init(void)
{
}

void SB_ShipMast_release(void)
{
}

void SB_ShipMast_initialise(void)
{
}

void SB_ShipMast_update(GameObject* obj)
{
    GameObject* parent;
    int phase;
    f32 speed;

    parent = obj->anim.parent;
    if (parent == NULL) return;
    phase = parent->unkF4;
    obj->anim.localPosX = lbl_803E586C;
    obj->anim.localPosY = lbl_803E586C;
    obj->anim.localPosZ = lbl_803E586C;
    if (((GameObject*)obj->anim.parent)->anim.seqId == SB_GALLEON_SEQID)
    {
        if (phase >= 0xa && phase < 0xd)
        {
            if (obj->anim.currentMove != 0)
            {
                ObjAnim_SetCurrentMove((int)obj, 0, lbl_803E586C, 0);
            }
            if (phase >= 0xc)
            {
                speed = lbl_803E5870;
            }
            else
            {
                speed = lbl_803E5874;
            }
        }
        else
        {
            if (obj->anim.currentMove != 1)
            {
                ObjAnim_SetCurrentMove((int)obj, 1, lbl_803E586C, 0);
            }
            speed = lbl_803E5878;
        }
    }
    else
    {
        if (obj->anim.currentMove != 1)
        {
            ObjAnim_SetCurrentMove((int)obj, 1, lbl_803E586C, 0);
        }
        speed = lbl_803E5878;
    }
    ((ObjAnimAdvanceObjectFirstF32Fn)ObjAnim_AdvanceCurrentMove)((int)obj, speed, (f32)(u32)framesThisStep, NULL);
}

int SB_ShipMast_getExtraSize(void) { return 0x0; }
int SB_ShipMast_getObjectTypeId(void) { return 0x0; }

void SB_ShipMast_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0)
    {
        objRenderFn_8003b8f4(lbl_803E5868);
    }
}
