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
#include "main/gamebit_ids.h"
#include "main/game_object.h"
#include "main/object_render.h"
#include "main/audio/sfx_ids.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/dll/DR/dll_0268_drcagecontrol.h"

int DR_CageControl_SeqFn(GameObject* obj)
{
    int ret;
    int placement = *(int*)&(obj)->anim.placementData;
    char* state = (obj)->extra;
    if (*(int*)state == 0)
    {
        if (mainGetBit(((CageControlPlacement*)placement)->armGameBit) != 0)
        {
            Sfx_StopObjectChannel((int)obj, 8);
            return 4;
        }
        if (((BitFlags8*)(state + 4))->b0 != mainGetBit(((CageControlPlacement*)placement)->watchGameBit))
        {
            Sfx_PlayFromObject((int)obj, SFXTRIG_mv_blkhit_c);
            Sfx_PlayFromObject((int)obj, SFXTRIG_mv_persquk2);
            if (mainGetBit(((CageControlPlacement*)placement)->watchGameBit) != 0)
            {
                Sfx_PlayFromObject((int)obj, SFXTRIG_mv_wickpickup16_194);
            }
            else
            {
                Sfx_StopObjectChannel((int)obj, 8);
            }
        }
        ((BitFlags8*)(state + 4))->b0 = mainGetBit(((CageControlPlacement*)placement)->watchGameBit);
    }
    ret = 0;
    if (*(int*)state == 0)
    {
        if (mainGetBit(((CageControlPlacement*)placement)->watchGameBit) == 0)
        {
            ret = 1;
        }
    }
    return ret;
}

int DR_CageControl_getExtraSize(void)
{
    return 0x4;
}

int DR_CageControl_getObjectTypeId(void)
{
    return 0x0;
}

void DR_CageControl_free(void)
{
}

void DR_CageControl_render(void* obj, u32 p2, u32 p3, u32 p4, u32 p5, char visible)
{
    if (visible != 0)
    {
        objRenderModelAndHitVolumesFwdDoubleLegacy(obj, p2, p3, p4, p5, (double)lbl_803E69D8);
    }
}

void DR_CageControl_hitDetect(void)
{
}

void DR_CageControl_update(GameObject* obj)
{
    int placement = *(int*)&(obj)->anim.placementData;
    char* state = (obj)->extra;
    if (((BitFlags8*)(state + 0x4))->b1 != 0)
    {
        return;
    }
    if (*(int*)state == 0 && mainGetBit(((CageControlPlacement*)placement)->armGameBit) != 0)
    {
        ((BitFlags8*)(state + 0x4))->b1 = 1;
        *(int*)state = 2;
    }
    if (((BitFlags8*)(state + 0x4))->b2 != 0)
    {
        ((BitFlags8*)(state + 0x4))->b1 = 1;
        (*gObjectTriggerInterface)->preempt((int)obj, 0x76c);
        if (mainGetBit(GAMEBIT_DR_EnteredDrakorTower) != 0)
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

void DR_CageControl_init(GameObject* obj, char* arg)
{
    char* state = obj->extra;
    obj->animEventCallback = DR_CageControl_SeqFn;
    if (mainGetBit(((CageControlPlacement*)arg)->armGameBit) != 0)
    {
        ((BitFlags8*)(state + 0x4))->b2 = 1;
        *(int*)state = 2;
    }
    else
    {
        *(int*)state = 0;
    }
}

void DR_CageControl_release(void)
{
}

void DR_CageControl_initialise(void)
{
}
