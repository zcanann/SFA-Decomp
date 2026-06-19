/*
 * cfperch (DLL 0x153) - the CloudRunner perch bird at CF. Squawks its
 * trigger sequence at the player once per spawn until the old
 * CloudRunner prisoner is freed, and notifies the flock when removed.
 * Carved from the sandwormBoss 10-DLL container.
 */
#include "main/game_object.h"
#include "main/dll/DR/sandwormBoss.h"
#include "main/objseq.h"

extern void ObjMsg_SendToObjects(int targetId, u32 flags, void* sender, u32 message, u32 param);
extern u32 GameBit_Get(int eventId);

/* perch anim-event callback: stop the sequence once the old
 * CloudRunner has been freed from his cage (0x4D) */
int fn_801A04F4(int obj, int unused, ObjAnimUpdateState* animUpdate)
{
    if (GameBit_Get(0x4d) != 0)
    {
        animUpdate->sequenceControlFlags = OBJSEQ_CONTROL_SET_LATCH_A;
    }
    return 0;
}

int cfperch_getExtraSize(void) { return 0x0; }

int cfperch_getObjectTypeId(void) { return 0x0; }

void cfperch_free(int* obj)
{
    ObjMsg_SendToObjects(62, 0, obj, 0x40001, 0);
}

void cfperch_render(void)
{
}

void cfperch_hitDetect(void)
{
}

void cfperch_update(int* obj)
{
    if (((GameObject*)obj)->unkF4 != 0)
    {
        if (GameBit_Get(0x50) == 0)
        {
            (*gObjectTriggerInterface)->runSequence(0, obj, -1);
        }
    }
    ((GameObject*)obj)->unkF4 = 0;
}

void cfperch_init(int* obj)
{
    ((GameObject*)obj)->unkF4 = 1;
    ((GameObject*)obj)->animEventCallback = fn_801A04F4;
}

void cfperch_release(void)
{
}

void cfperch_initialise(void)
{
}
