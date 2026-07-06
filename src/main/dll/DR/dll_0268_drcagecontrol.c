/*
 * drcagecontrol (DLL 0x268) - drives a cage that opens in response to
 * game bits. The placement supplies the game bit that arms the cage
 * (unk1E) and the bit watched by the trigger callback to play the
 * pickup sfx and report completion (unk20).
 *
 * The 4-byte extra holds the runtime sequence id (offset 0) plus a
 * BitFlags8 status byte at offset 4 (b0/b1/b2).
 */
#include "main/dll/DR/dr_shared.h"
#include "main/game_object.h"

#include "main/audio/sfx_ids.h"

typedef struct CageControlPlacement
{
    u8 pad0[0x1E - 0x0];
    s16 armGameBit;    /* 0x1E: game bit that pre-opens the cage */
    s16 watchGameBit;  /* 0x20: drives the pickup sfx + completion */
    u8 pad22[0x28 - 0x22];
} CageControlPlacement;

STATIC_ASSERT(offsetof(CageControlPlacement, armGameBit) == 0x1E);
STATIC_ASSERT(offsetof(CageControlPlacement, watchGameBit) == 0x20);
STATIC_ASSERT(sizeof(CageControlPlacement) == 0x28);

void cagecontrol_free(void)
{
}

int cagecontrol_getExtraSize(void) { return 0x4; }

int cagecontrol_getObjectTypeId(void) { return 0x0; }

void cagecontrol_hitDetect(void)
{
}

void cagecontrol_initialise(void)
{
}

void cagecontrol_release(void)
{
}

void cagecontrol_render(void* obj, u32 p2, u32 p3, u32 p4, u32 p5, char visible)
{
    if (visible != 0)
    {
        objRenderModelAndHitVolumes(obj, p2, p3, p4, p5, (double)lbl_803E69D8);
    }
}

void cagecontrol_init(int obj, char* arg)
{
    char* state = ((GameObject*)obj)->extra;
    ((GameObject*)obj)->animEventCallback = cagecontrol_updateTriggerCallback;
    if (GameBit_Get(((CageControlPlacement*)arg)->armGameBit) != 0)
    {
        ((BitFlags8*)(state + 0x4))->b2 = 1;
        *(int*)state = 2;
    }
    else
    {
        *(int*)state = 0;
    }
}

void cagecontrol_update(int obj)
{
    int placement = *(int*)&((GameObject*)obj)->anim.placementData;
    char* state = ((GameObject*)obj)->extra;
    if (((BitFlags8*)(state + 0x4))->b1 != 0)
    {
        return;
    }
    if (*(int*)state == 0 && GameBit_Get(((CageControlPlacement*)placement)->armGameBit) != 0)
    {
        ((BitFlags8*)(state + 0x4))->b1 = 1;
        *(int*)state = 2;
    }
    if (((BitFlags8*)(state + 0x4))->b2 != 0)
    {
        ((BitFlags8*)(state + 0x4))->b1 = 1;
        (*gObjectTriggerInterface)->preempt(obj, 0x76c);
        if (GameBit_Get(0x9f3) != 0)
        {
            (*gObjectTriggerInterface)->runSequence(*(int*)state, (void*)obj, 0x60);
        }
        else
        {
            (*gObjectTriggerInterface)->runSequence(*(int*)state, (void*)obj, 0x70);
        }
    }
    else
    {
        (*gObjectTriggerInterface)->runSequence(*(int*)state, (void*)obj, -1);
    }
}

int cagecontrol_updateTriggerCallback(int obj)
{
    int ret;
    int placement = *(int*)&((GameObject*)obj)->anim.placementData;
    char* state = ((GameObject*)obj)->extra;
    if (*(int*)state == 0)
    {
        if (GameBit_Get(((CageControlPlacement*)placement)->armGameBit) != 0)
        {
            Sfx_StopObjectChannel(obj, 8);
            return 4;
        }
        if (((BitFlags8*)(state + 4))->b0 != GameBit_Get(((CageControlPlacement*)placement)->watchGameBit))
        {
            Sfx_PlayFromObject(obj, SFXar_ring_pickup);
            Sfx_PlayFromObject(obj, SFXar_generic_pickup);
            if (GameBit_Get(((CageControlPlacement*)placement)->watchGameBit) != 0)
            {
                Sfx_PlayFromObject(obj, SFXar_bomb_pickup);
            }
            else
            {
                Sfx_StopObjectChannel(obj, 8);
            }
        }
        ((BitFlags8*)(state + 4))->b0 = GameBit_Get(((CageControlPlacement*)placement)->watchGameBit);
    }
    ret = 0;
    if (*(int*)state == 0)
    {
        if (GameBit_Get(((CageControlPlacement*)placement)->watchGameBit) == 0)
        {
            ret = 1;
        }
    }
    return ret;
}
