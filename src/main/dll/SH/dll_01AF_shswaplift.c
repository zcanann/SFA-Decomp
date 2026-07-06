/*
 * shswaplift / warpstonelift (DLL 0x1AF) - the WarpStone lift platform.
 *
 * The platform tracks whether a relevant character is standing in range
 * (scanning the per-object proximity list), then runs a small state
 * machine: while a character is present it offers the WarpStone (item /
 * bit 0xC7C) via the Y-button menu, and once the trigger fires it sets
 * the progress bits and locks into the "swapped" state. Out of range it
 * disables its hit volume.
 */
#include "main/game_object.h"
#include "main/gamebits.h"
#include "main/dll/VF/vf_shared.h"
#include "sfa_light_decls.h"

/* state byte (extra+0) progression */
#define WARPSTONELIFT_STATE_IDLE     0 /* not yet swapped; character out of / entering range */
#define WARPSTONELIFT_STATE_OFFERING 1 /* character present, WarpStone offered via Y-menu */
#define WARPSTONELIFT_STATE_SWAPPED  2 /* WarpStone taken; locked */

/* WarpStone item / game bit offered by this lift */
#define WARPSTONELIFT_ITEM_BIT 0xC7C

extern f32 lbl_803E54C8;
extern s32 lbl_803DC058[2]; /* the two "already-swapped" progress bits */
extern u16 getYButtonItem(s16* out);

extern int ObjTrigger_IsSetById(int obj, int id);
extern int ObjTrigger_IsSet(int obj);

void warpstonelift_free(void)
{
}

void warpstonelift_hitDetect(void)
{
}

void warpstonelift_release(void)
{
}

void warpstonelift_initialise(void)
{
}

int warpstonelift_getExtraSize(void) { return 0x1; }
int warpstonelift_getObjectTypeId(void) { return 0x0; }

void warpstonelift_init(int obj, s8* def)
{
    int* state = ((GameObject*)obj)->extra;
    int i;
    ((GameObject*)obj)->anim.rotX = (s16)((s32)def[0x18] << 8);
    ((GameObject*)obj)->unkF4 = 0;
    for (i = 0; i < 2; i++)
    {
        if (GameBit_Get(lbl_803DC058[i]) != 0)
        {
            *(u8*)state = (u8)(i + 1);
        }
    }
    switch (*(u8*)state)
    {
    case WARPSTONELIFT_STATE_IDLE:
    case WARPSTONELIFT_STATE_SWAPPED:
        Obj_SetActiveHitVolumeBounds((GameObject*)obj, 0, 0, 0, 0, 3);
        break;
    case WARPSTONELIFT_STATE_OFFERING:
        Obj_SetActiveHitVolumeBounds((GameObject*)obj, 0, 0, 0, 0, 4);
        break;
    }
}

void warpstonelift_update(u8* obj)
{
    u8* state = ((GameObject*)obj)->extra;
    int off;
    char* list;
    int found = 0;
    int count;
    int i;
    s16 item;

    list = *(char**)(obj + 0x58);
    count = *(s8*)(list + 0x10F);
    if (count > 0)
    {
        off = 0;
        for (i = 0; i < count; i++)
        {
            char* other = *(char**)(list + off + 0x100);
            if (((GameObject*)other)->anim.classId == 1)
            {
                found = 1;
            }
            off += 4;
        }
    }
    if (found)
    {
        ((GameObject*)obj)->anim.resetHitboxFlags &= ~INTERACT_FLAG_DISABLED;
        switch (*state)
        {
        case WARPSTONELIFT_STATE_IDLE:
        case WARPSTONELIFT_STATE_OFFERING:
            getYButtonItem(&item);
            if ((GameBit_Get(WARPSTONELIFT_ITEM_BIT) != 0 && cMenuGetSelectedItem() != -1) ||
                item == WARPSTONELIFT_ITEM_BIT)
            {
                Obj_SetActiveHitVolumeBounds((GameObject*)obj, 0, 0, 0, 0, 4);
            }
            else
            {
                Obj_SetActiveHitVolumeBounds((GameObject*)obj, 0, 0, 0, 0, 2);
            }
            if (ObjTrigger_IsSetById((int)obj, WARPSTONELIFT_ITEM_BIT) != 0)
            {
                GameBit_Set(0x886, 1);
                GameBit_Set(0xC7D, 1);
                *state = WARPSTONELIFT_STATE_SWAPPED;
                Obj_SetActiveHitVolumeBounds((GameObject*)obj, 0, 0, 0, 0, 3);
            }
            else if (ObjTrigger_IsSet((int)obj) != 0)
            {
                GameBit_Set(0xC7E, 1);
            }
            break;
        case WARPSTONELIFT_STATE_SWAPPED:
            if (ObjTrigger_IsSet((int)obj) != 0)
            {
                GameBit_Set(0x886, 1);
            }
            break;
        }
    }
    else
    {
        ((GameObject*)obj)->anim.resetHitboxFlags |= INTERACT_FLAG_DISABLED;
    }
}

void warpstonelift_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0) objRenderModelAndHitVolumes(p1, p2, p3, p4, p5, lbl_803E54C8);
}
