/*
 * cfperch (DLL 0x153) - the CloudRunner perch bird at CF. Squawks its
 * trigger sequence at the player once per spawn until the old
 * CloudRunner prisoner is freed, and notifies the flock when removed.
 * Carved from the sandwormBoss 10-DLL container.
 */
#include "main/game_object.h"
#include "main/dll/CF/dll_0153_cfperch.h"
#include "main/objseq.h"
#include "main/obj_message.h"
#include "main/gamebits.h"
#include "main/gamebit_ids.h"

/* perch anim-event callback: stop the sequence once the old
 * CloudRunner has been freed from his cage (0x4D) */
int CFPerch_SeqFn(int obj, int unused, ObjAnimUpdateState* animUpdate)
{
    if (mainGetBit(GAMEBIT_CFPerchRelated004D) != 0)
    {
        animUpdate->sequenceControlFlags = OBJSEQ_CONTROL_SET_LATCH_A;
    }
    return 0;
}

int cfperch_getExtraSize(void)
{
    return 0x0;
}

int cfperch_getObjectTypeId(void)
{
    return 0x0;
}

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
        if (mainGetBit(GAMEBIT_CF_UncleFlewOff) == 0)
        {
            (*gObjectTriggerInterface)->runSequence(0, obj, -1);
        }
    }
    ((GameObject*)obj)->unkF4 = 0;
}

void cfperch_init(int* obj)
{
    ((GameObject*)obj)->unkF4 = 1;
    ((GameObject*)obj)->animEventCallback = CFPerch_SeqFn;
}

void cfperch_release(void)
{
}

void cfperch_initialise(void)
{
}
