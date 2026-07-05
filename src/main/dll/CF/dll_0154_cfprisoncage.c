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
#include "main/obj_placement.h"
#include "main/dll/DR/sandwormBoss.h"
#include "main/objseq.h"
#include "main/dll/fx_800944A0_shared.h"

typedef struct CfPrisonCageMapData
{
    ObjPlacement base;
    s16 openedBit; /* 0x18: game bit set once the cage is opened */
} CfPrisonCageMapData;

/* placement type ids this DLL serves (anim.seqId carries the romlist
   type; retail names CFPrisonCage / CFCageSwitch): the cage runs
   sequence 0, the switch reports object type 8 and runs sequence 1. */
enum
{
    CFPRISONCAGE_TYPE_CAGE = 0x127,
    CFPRISONCAGE_TYPE_SWITCH = 0x128
};

typedef struct CfPrisonCageObjectDef
{
    u8 pad0[0x8 - 0x0];
    f32 posX; /* 0x08 */
    f32 posY; /* 0x0C */
    f32 posZ; /* 0x10 */
    u8 pad14[0x18 - 0x14];
    s16 openedBit; /* 0x18: game bit set once the cage is opened */
    s16 rotY;      /* 0x1A: spawn yaw byte, shifted <<8 into anim.rotX */
    u8 pad1C[0x1E - 0x1C];
    s16 unk1E;
    u8 pad20[0x22 - 0x20];
    s16 unk22;
    u8 pad24[0x28 - 0x24];
} CfPrisonCageObjectDef;

STATIC_ASSERT(offsetof(CfPrisonCageMapData, openedBit) == 0x18);

/* generic activate message granting the opened bit (switch path only;
   the same id powers a base in cfpowerbase) */
#define CFPRISONCAGE_MSG_OPEN 0xA0005

extern int ObjMsg_Pop();
extern void ObjMsg_AllocQueue(void* obj, int capacity);
extern void objRenderFn_8003b8f4(int obj, int p2, int p3, int p4, int p5, f32 scale);
extern u32 GameBit_Get(int eventId);
extern f32 lbl_803E42B0;
extern f32 lbl_803E42B4;
extern int ObjHits_GetPriorityHitWithPosition(int* obj, int a, int b, int c, f32* out_x, f32* out_y, f32* out_z);

/* cfprisoncage_SeqFn: lock interaction once the opened bit is set;
 * everything past the cage early-return is the SWITCH's logic - drain
 * the message queue (granting the opened bit on the keyed message),
 * mirror the 0x44 event into the prompt flags and run the open
 * sequence once it is ready. */
int cfprisoncage_SeqFn(int* obj, int unused, ObjAnimUpdateState* animUpdate)
{
    int msg;
    int v;
    int w = 0;
    CfPrisonCageMapData* data = (CfPrisonCageMapData*)((GameObject*)obj)->anim.placement;
    if (GameBit_Get(data->openedBit) != 0)
    {
        ((GameObject*)obj)->anim.resetHitboxFlags = (u8)(((GameObject*)obj)->anim.resetHitboxFlags | INTERACT_FLAG_DISABLED);
        animUpdate->sequenceControlFlags |= OBJSEQ_CONTROL_SET_LATCH_A;
        return 0;
    }
    if (((GameObject*)obj)->anim.seqId == CFPRISONCAGE_TYPE_CAGE)
    {
        return 0;
    }
    while (ObjMsg_Pop(obj, &msg, &v, &w) != 0)
    {
        switch (msg)
        {
        case CFPRISONCAGE_MSG_OPEN:
            GameBit_Set(data->openedBit, 1);
            break;
        }
    }
    /* 0x44: the free-the-prisoner event (also stands the guard down -
       see cfprisonguard) */
    if (GameBit_Get(0x44) != 0)
    {
        ((GameObject*)obj)->anim.resetHitboxFlags = (u8)(((GameObject*)obj)->anim.resetHitboxFlags & ~INTERACT_FLAG_PROMPT_SUPPRESSED);
    }
    else
    {
        ((GameObject*)obj)->anim.resetHitboxFlags = (u8)(((GameObject*)obj)->anim.resetHitboxFlags | INTERACT_FLAG_PROMPT_SUPPRESSED);
    }
    if ((((GameObject*)obj)->anim.resetHitboxFlags & INTERACT_FLAG_ACTIVATED) != 0)
    {
        if ((*gGameUIInterface)->isEventReady(0x44) != 0)
        {
            ((GameObject*)obj)->anim.resetHitboxFlags = (u8)(
                ((GameObject*)obj)->anim.resetHitboxFlags | INTERACT_FLAG_DISABLED);
            (*gObjectTriggerInterface)->runSequence(0, obj, -1);
        }
    }
    return 0;
}

int cfprisoncage_getExtraSize(void) { return 0x0; }

int cfprisoncage_getObjectTypeId(int* obj)
{
    if (((GameObject*)obj)->anim.seqId == CFPRISONCAGE_TYPE_SWITCH) return 0x8;
    return 0x0;
}

void cfprisoncage_free(void)
{
}

void cfprisoncage_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0) objRenderFn_8003b8f4(p1, p2, p3, p4, p5, lbl_803E42B0);
}

void cfprisoncage_hitDetect(int* obj)
{
    f32 pos_z, pos_y, pos_x;
    if (ObjHits_GetPriorityHitWithPosition(obj, 0, 0, 0, &pos_x, &pos_y, &pos_z) != 0)
    {
        objfx_spawnHitEmitterAtPos(&pos_x, 8, 200, 128, 0);
    }
}

void cfprisoncage_update(int* obj)
{
    int v;
    if (((GameObject*)obj)->unkF4 != 0)
    {
        switch (((GameObject*)obj)->anim.seqId)
        {
        case CFPRISONCAGE_TYPE_CAGE: v = 0;
            break;
        case CFPRISONCAGE_TYPE_SWITCH:
        default: v = 1;
            break;
        }
        (*gObjectTriggerInterface)->runSequence(v, obj, -1);
        ((GameObject*)obj)->unkF4 = 0;
    }
}

void cfprisoncage_init(int* obj, u8* def)
{
    ObjMsg_AllocQueue(obj, 1);
    ((GameObject*)obj)->anim.rotX = (s16)((s32)def[0x1a] << 8);
    ((GameObject*)obj)->unkF4 = 1;
    ((GameObject*)obj)->animEventCallback = cfprisoncage_SeqFn;
    /* switch: pose thrown/reset from the bit; cage: jump the open
       sequence forward when already opened */
    if (((GameObject*)obj)->anim.seqId == CFPRISONCAGE_TYPE_SWITCH)
    {
        if (GameBit_Get(((CfPrisonCageObjectDef*)def)->openedBit) != 0)
        {
            ObjAnim_SetCurrentMove((int)obj, 1, lbl_803E42B4, 0);
        }
        else
        {
            ObjAnim_SetCurrentMove((int)obj, 0, lbl_803E42B4, 0);
        }
    }
    else
    {
        if (GameBit_Get(((CfPrisonCageObjectDef*)def)->openedBit) != 0)
        {
            (*gObjectTriggerInterface)->preempt((int)obj, 60);
        }
    }
}

void cfprisoncage_release(void)
{
}

void cfprisoncage_initialise(void)
{
}
