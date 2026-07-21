/*
 * cfprisoncage (DLL 0x154) - the CloudRunner dungeon prison cages and
 * their release switch. clouddungeon places four cages whose opened
 * bits are 0x4C-0x4F; 0x4D is the old CloudRunner's cage (see
 * cfprisonuncle) and 0x4E the caged guardian's (see cfguardian). The
 * SeqFn locks interaction once a cage's opened bit is set; the rest of
 * its logic (granting the bit on the 0xA0005 message, mirroring the
 * 0x44 event into the prompt bits, running the open sequence) belongs
 * to the switch type, which ships no placements in v1.0 - the cage
 * bits are set by sequence scripts instead. Carved from the
 * sandwormBoss 10-DLL container.
 */

#include "main/game_ui_interface.h"
#include "main/game_object.h"
#include "main/objhits.h"
#include "main/object_render.h"
#include "main/obj_message.h"
#include "main/obj_placement.h"
#include "main/dll/CF/dll_0154_cfprisoncage.h"
#include "main/objseq.h"
#include "main/gamebit_ids.h"
#include "main/gamebits_api.h"
#include "main/object_descriptor.h"

/* placement type ids this DLL serves (anim.seqId carries the romlist
   type; retail names CFPrisonCage / CFCageSwitch): the cage runs
   sequence 0, the switch reports object type 8 and runs sequence 1. */
enum
{
    CFPRISONCAGE_TYPE_CAGE = 0x127,
    CFPRISONCAGE_TYPE_SWITCH = 0x128
};

/* generic activate message granting the opened bit (switch path only;
   the same id powers a base in cfpowerbase) */
#define CFPRISONCAGE_MSG_OPEN 0xA0005
#define CFPRISONCAGE_OPEN_EVENT 0x44

/* CFPrisonCage_SeqFn: lock interaction once the opened bit is set;
 * everything past the cage early-return is the SWITCH's logic - drain
 * the message queue (granting the opened bit on the keyed message),
 * mirror the 0x44 event into the prompt flags and run the open
 * sequence once it is ready. */
int CFPrisonCage_SeqFn(GameObject* obj, int unused, ObjAnimUpdateState* animUpdate)
{
    int msg;
    int sender;
    int param = 0;
    CfPrisonCagePlacement* placement = (CfPrisonCagePlacement*)obj->anim.placement;
    if (mainGetBit(placement->openedGameBit) != 0)
    {
        obj->anim.resetHitboxFlags = (u8)(obj->anim.resetHitboxFlags | INTERACT_FLAG_DISABLED);
        animUpdate->sequenceControlFlags |= OBJSEQ_CONTROL_SET_LATCH_A;
        return 0;
    }
    if (obj->anim.seqId == CFPRISONCAGE_TYPE_CAGE)
    {
        return 0;
    }
    while (ObjMsg_Pop(obj, (u32*)&msg, (u32*)&sender, (u32*)&param) != 0)
    {
        switch (msg)
        {
        case CFPRISONCAGE_MSG_OPEN:
            mainSetBits(placement->openedGameBit, 1);
            break;
        }
    }
    /* 0x44: the free-the-prisoner event (also stands the guard down -
       see cfprisonguard) */
    if (mainGetBit(GAMEBIT_ITEM_PrisonKey_Got) != 0)
    {
        obj->anim.resetHitboxFlags =
            (u8)(obj->anim.resetHitboxFlags & ~INTERACT_FLAG_PROMPT_SUPPRESSED);
    }
    else
    {
        obj->anim.resetHitboxFlags =
            (u8)(obj->anim.resetHitboxFlags | INTERACT_FLAG_PROMPT_SUPPRESSED);
    }
    if ((obj->anim.resetHitboxFlags & INTERACT_FLAG_ACTIVATED) != 0)
    {
        if ((*gGameUIInterface)->isEventReady(CFPRISONCAGE_OPEN_EVENT) != 0)
        {
            obj->anim.resetHitboxFlags = (u8)(obj->anim.resetHitboxFlags | INTERACT_FLAG_DISABLED);
            (*gObjectTriggerInterface)->runSequence(0, obj, -1);
        }
    }
    return 0;
}

int CFPrisonCage_getExtraSize(void)
{
    return 0x0;
}

int CFPrisonCage_getObjectTypeId(GameObject* obj)
{
    if (obj->anim.seqId == CFPRISONCAGE_TYPE_SWITCH)
        return 0x8;
    return 0x0;
}

void CFPrisonCage_free(void)
{
}

void CFPrisonCage_render(GameObject* obj, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 isVisible = visible;
    if (isVisible != 0)
        objRenderModelAndHitVolumes(obj, p2, p3, p4, p5, 1.0f);
}

void CFPrisonCage_hitDetect(GameObject* obj)
{
    f32 pos_z, pos_y, pos_x;
    if (ObjHits_GetPriorityHitWithPosition(obj, 0, 0, 0, &pos_x, &pos_y, &pos_z) != 0)
    {
        objfx_spawnHitEmitterAtPos(&pos_x, 8, 200, 128, 0);
    }
}

void CFPrisonCage_update(GameObject* obj)
{
    int seqIndex;
    if (obj->userData1 != 0)
    {
        switch (obj->anim.seqId)
        {
        case CFPRISONCAGE_TYPE_CAGE:
            seqIndex = 0;
            break;
        case CFPRISONCAGE_TYPE_SWITCH:
        default:
            seqIndex = 1;
            break;
        }
        (*gObjectTriggerInterface)->runSequence(seqIndex, obj, -1);
        obj->userData1 = 0;
    }
}

void CFPrisonCage_init(GameObject* obj, CfPrisonCagePlacement* placement)
{
    ObjMsg_AllocQueue(obj, 1);
    obj->anim.rotX = (s16)((s32)placement->rotByte << 8);
    obj->userData1 = 1;
    obj->animEventCallback = CFPrisonCage_SeqFn;
    /* switch: pose thrown/reset from the bit; cage: jump the open
       sequence forward when already opened */
    if (obj->anim.seqId == CFPRISONCAGE_TYPE_SWITCH)
    {
        if (mainGetBit(placement->openedGameBit) != 0)
        {
            ObjAnim_SetCurrentMove((int)obj, 1, 0.0f, 0);
        }
        else
        {
            ObjAnim_SetCurrentMove((int)obj, 0, 0.0f, 0);
        }
    }
    else
    {
        if (mainGetBit(placement->openedGameBit) != 0)
        {
            (*gObjectTriggerInterface)->preempt((int)obj, 60);
        }
    }
}

void CFPrisonCage_release(void)
{
}

void CFPrisonCage_initialise(void)
{
}

ObjectDescriptor gCFPrisonCageObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)CFPrisonCage_initialise,
    (ObjectDescriptorCallback)CFPrisonCage_release,
    0,
    (ObjectDescriptorCallback)CFPrisonCage_init,
    (ObjectDescriptorCallback)CFPrisonCage_update,
    (ObjectDescriptorCallback)CFPrisonCage_hitDetect,
    (ObjectDescriptorCallback)CFPrisonCage_render,
    (ObjectDescriptorCallback)CFPrisonCage_free,
    (ObjectDescriptorCallback)CFPrisonCage_getObjectTypeId,
    CFPrisonCage_getExtraSize,
};
