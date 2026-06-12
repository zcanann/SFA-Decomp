/*
 * cfperch (DLL 0x153) - the CloudRunner perch bird at CF. Squawks its
 * trigger sequence at the player once per spawn until the prisoners
 * are freed, and notifies the flock when removed. Carved from the
 * sandwormBoss 10-DLL container.
 */
#include "main/effect_interfaces.h"
#include "main/game_object.h"
#include "main/audio/sfx_ids.h"
#include "main/dll/DR/sandwormBoss.h"
#include "main/objseq.h"

extern int ObjMsg_SendToObjects();
extern ObjectTriggerInterface** gObjectTriggerInterface;
extern uint GameBit_Get(int eventId);

void cfperch_render(void)
{
}

void cfperch_hitDetect(void)
{
}

void cfperch_release(void)
{
}

void cfperch_initialise(void)
{
}

int cfperch_getExtraSize(void) { return 0x0; }

int cfperch_getObjectTypeId(void) { return 0x0; }

/* perch anim-event callback: stop the sequence once the player has
 * been captured (0x4D) */
int fn_801A04F4(int obj, int unused, ObjAnimUpdateState* animUpdate)
{
    if (GameBit_Get(0x4d) != 0)
    {
        animUpdate->sequenceControlFlags = 4;
    }
    return 0;
}

void cfperch_init(int* obj)
{
    ((GameObject*)obj)->unkF4 = 1;
    ((GameObject*)obj)->animEventCallback = (void*)fn_801A04F4;
}

void cfperch_free(int* obj)
{
    ObjMsg_SendToObjects(62, 0, obj, 0x40001, 0);
}

void cfperch_update(int* obj)
{
    if (((GameObject*)obj)->unkF4 != 0)
    {
        /* squawk at the player until the prisoners are freed (0x50) */
        if (GameBit_Get(0x50) == 0)
        {
            (*gObjectTriggerInterface)->runSequence(0, obj, -1);
        }
    }
    ((GameObject*)obj)->unkF4 = 0;
}
