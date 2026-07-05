/*
 * DLL 0x01F6 - Flag (decorative flag object). TU: 0x801E5DC4-0x801E5F74.
 *
 * A passive cloth/flag prop animated through ObjAnim moves. Behaviour is
 * selected by the object's current animation seqId:
 *   0x187  - advance the idle flutter move by framesThisStep.
 *   0x803  - "tied" flag: track the linked parent object. While the parent
 *            holds object flag 0x1000 the flag stays slack (velocityX from
 *            lbl_803E5998); otherwise it swings, deriving velocityX from the
 *            parent's rotZ and integrating it into its own rotZ.
 *   other  - advance the default flutter move by framesThisStep.
 * init seeds rotX from the placement byte and starts the flutter move for
 * everything except the tied (0x803) variant. render draws the model when
 * visible.
 */
#include "main/game_object.h"
#include "main/dll/VF/vf_shared.h"
extern f32 lbl_803E59A8;
extern f32 lbl_803E5998;
extern f32 lbl_803E599C;
extern f32 lbl_803E59AC;
extern f32 lbl_803E59B0;

enum
{
    FLAG_SEQ_FLUTTER = 0x187,
    FLAG_SEQ_TIED = 0x803
};

#define FLAG_PARENT_SLACK_FLAG 0x1000

/* placement-record byte seeding the flag's initial rotX */
#define FLAG_MAPDATA_ROT_X_BYTE_OFF 0x18

void Flag_free(void)
{
}

void Flag_hitDetect(void)
{
}

void Flag_release(void)
{
}

void Flag_initialise(void)
{
}

int Flag_getExtraSize(void) { return 0x0; }
int Flag_getObjectTypeId(void) { return 0x0; }

void Flag_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    if (visible != 0) objRenderFn_8003b8f4(p1, p2, p3, p4, p5, lbl_803E59A8);
}

void Flag_init(int* obj, int* def)
{
    if (((GameObject*)obj)->anim.seqId != FLAG_SEQ_TIED)
    {
        ((GameObject*)obj)->anim.rotX =
            (s16)((s32) * (s8*)((char*)def + FLAG_MAPDATA_ROT_X_BYTE_OFF) << 8);
        ObjAnim_SetCurrentMove((int)obj, 0, lbl_803E5998, 0);
    }
}

void Flag_update(int obj)
{
    int linkedObj;

    if (((GameObject*)obj)->anim.seqId == FLAG_SEQ_FLUTTER)
    {
        ((ObjAnimAdvanceObjectFirstF32Fn)ObjAnim_AdvanceCurrentMove)(obj, lbl_803E59AC,
                                                                     (f32)(u32)framesThisStep,
                                                                     NULL);
    }
    else if (((GameObject*)obj)->anim.seqId == FLAG_SEQ_TIED)
    {
        Obj_GetPlayerObject();
        linkedObj = *(int*)&((GameObject*)obj)->anim.parent;
        if ((((GameObject*)linkedObj)->objectFlags & FLAG_PARENT_SLACK_FLAG) != 0)
        {
            ((GameObject*)obj)->anim.velocityX = lbl_803E5998;
        }
        else
        {
            ((GameObject*)obj)->anim.velocityX = (f32)((GameObject*)linkedObj)->anim.rotZ * lbl_803E599C;
            ((GameObject*)obj)->anim.rotZ = (s16)(
                (f32)((GameObject*)obj)->anim.rotZ + ((GameObject*)obj)->anim.velocityX);
        }
    }
    else
    {
        ((ObjAnimAdvanceObjectFirstF32Fn)ObjAnim_AdvanceCurrentMove)(obj, lbl_803E59B0,
                                                                     (f32)(u32)framesThisStep,
                                                                     NULL);
    }
}
