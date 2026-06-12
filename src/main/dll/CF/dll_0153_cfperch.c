/*
 * DLL 0x153 - CFPerch; 10-DLL container spanning 0x14A CFPowerBase
 * through 0x157 SpiritDoorSpirit [8019D578-801A0B14). DLLs 0x148/0x149
 * are owned by dll_0148_cfguardian.c / dll_0149_cfwindlift.c; their
 * definitions here are collapsed to prototypes.
 */
#include "main/effect_interfaces.h"
#include "main/game_object.h"
#include "main/audio/sfx_ids.h"
#include "main/dll/DR/sandwormBoss.h"
#include "main/objseq.h"

extern undefined4 ObjHits_EnableObject();
extern undefined8 ObjMsg_SendToObjects();

extern ObjectTriggerInterface** gObjectTriggerInterface;

extern uint GameBit_Get(int eventId);
extern void fn_8003ADC4(int* a, int* b, void* c, int d, int e, int f);


void babycloudrunner_init_OLD_v1_1(int obj)
{
    undefined4* state;

    state = ((GameObject*)obj)->extra;
    *state = 0;
    state[1] = 0;
    ObjHits_EnableObject(obj);
    ((GameObject*)obj)->anim.alpha = 0x80;
    return;
}


void cfguardian_release(void);

/* Per-object extra state for the CloudRunner guardian
 * (cfguardian_getExtraSize == 0xa9c). */

/* Per-object extra state for the CloudRunner main crystal
 * (cfmaincrystal_getExtraSize == 0x160). */


/* Per-object extra state for the CloudRunner power base
 * (cfpowerbase_getExtraSize == 0x6). */


/* Per-object extra state for the CloudRunner prison guard
 * (cfprisonguard_getExtraSize == 0x3c). */


/* Per-object extra state for the CloudRunner prison uncle
 * (cfprisonuncle_getExtraSize == 0xa8). */


/* Per-object extra state for the robot light beacon
 * (gcrobotlightbea_getExtraSize == 0xc). */


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

void cfprisoncage_free(void);

int cfperch_getExtraSize(void) { return 0x0; }
int cfperch_getObjectTypeId(void) { return 0x0; }
int cfprisoncage_getExtraSize(void);

#pragma scheduling off
int fn_801A04F4(int obj, int unused, ObjAnimUpdateState* animUpdate)
{
    if (GameBit_Get(0x4d) != 0)
    {
        animUpdate->sequenceControlFlags = 4;
    }
    return 0;
}

#pragma peephole off
void cfperch_init(int* obj)
{
    ((GameObject*)obj)->unkF4 = 1;
    ((GameObject*)obj)->animEventCallback = (void*)fn_801A04F4;
}

void cfmaincrystal_free(int* obj);

void cfperch_free(int* obj)
{
    ObjMsg_SendToObjects(62, 0, obj, 0x40001, 0);
}

void babycloudrunner_free(int* obj);

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
