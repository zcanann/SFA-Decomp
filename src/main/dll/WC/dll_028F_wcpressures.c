/*
 * wcpressures (DLL 0x28F) - a weighted pressure plate in the Walled City
 * (WC). The plate lowers while something heavy rests on it and rises again
 * when the weight is removed, latching a "solved" game bit while pressed.
 * Each update scans the object's hit list for entities standing higher than
 * triggerHeight above the plate, tracks up to WCPRESSURES_TRACKED_COUNT of
 * them with their saved XZ positions, and counts the plate pressed while any
 * tracked entity stays put. A 4-mode machine (RAISED -> LOWERING -> PRESSED
 * -> RISING) animates localPosY between the setup Y and Y - pressDepth,
 * plays a sfx at the transitions, sets/clears solvedBit and swaps the plate
 * texture while down. activateBit, when set, gates the whole object inert.
 * The animEventCallback snapshots tracked-tile positions or resets the
 * object and clears solvedBit.
 */
#include "main/audio/sfx.h"
#include "main/frame_timing.h"
#include "main/gamebits.h"
#include "main/gameplay_runtime.h"
#include "main/objanim_update.h"
#include "main/obj_group.h"
#include "main/objtexture.h"
#include "main/debug.h"
#include "main/dll/dll_0293_suntemple.h"
#include "main/dll/dll_0294_wctemple.h"
#include "main/dll/WC/dll_0292_wctrexstatu.h"
#include "main/dll/WC/dll_028F_wcpressures.h"
#include "main/dll/WC/dll_0295_wcapertures.h"
#include "main/dll/dll_0299.h"
#include "main/game_object.h"

#include "main/audio/sfx_ids.h"
#include "main/audio/sfx_trigger_ids.h"

#define WCPRESSURES_EXTRA_SIZE        0x7c
#define WCPRESSURES_OBJECT_GROUP      0x31
#define WCPRESSURES_RENDER_TYPE_BASE  0x400
#define WCPRESSURES_RENDER_TYPE_SHIFT 0xb

#define WCPRESSURES_MODE_RAISED   0
#define WCPRESSURES_MODE_RISING   1
#define WCPRESSURES_MODE_PRESSED  2
#define WCPRESSURES_MODE_LOWERING 3

#define WCPRESSURES_FOUND_TIMER  5
#define WCPRESSURES_SOLVED_TIMER 0x1e

#define WCPRESSURES_OBJECT_SETUP_OFFSET 0x4c
#define WCPRESSURES_OBJECT_Y_OFFSET     0x10
#define WCPRESSURES_OBJECT_Z_OFFSET     0x14
#define WCPRESSURES_OBJECT_STATE_OFFSET 0xb8

#define WCPRESSURES_CALLBACK_NONE           0
#define WCPRESSURES_CALLBACK_SNAPSHOT_TILES 1
#define WCPRESSURES_CALLBACK_RESET          2

#define WCPRESSURES_HITLIST_OFFSET         0x58
#define WCPRESSURES_HITLIST_OBJECTS_OFFSET 0x100
#define WCPRESSURES_HITLIST_COUNT_OFFSET   0x10f

#define WCPRESSURES_TEXTURE_DEFAULT 0
#define WCPRESSURES_TEXTURE_PRESSED 1
#define WCPRESSURES_TEXTURE_SHIFT   8

#define WCPRESSURES_OBJFLAG_HIDDEN             0x4000
#define WCPRESSURES_OBJFLAG_HITDETECT_DISABLED 0x2000

int wcpressures_getExtraSize(void)
{
    return WCPRESSURES_EXTRA_SIZE;
}

int wcpressures_SeqFn(GameObject* obj, int unused, ObjAnimUpdateState* animUpdate)
{
    WCPressuresState* state = (WCPressuresState*)obj->extra;
    WCPressuresSetup* setup = (WCPressuresSetup*)obj->anim.placementData;
    u8 i;

    if (animUpdate->triggerCommand == WCPRESSURES_CALLBACK_SNAPSHOT_TILES)
    {
        for (i = 0; i < WCPRESSURES_TRACKED_COUNT; i++)
        {
            if ((void*)state->objects[i] != NULL)
            {
                state->savedPos[i].x = state->objects[i]->anim.localPosX;
                state->savedPos[i].z = state->objects[i]->anim.localPosZ;
            }
        }
        animUpdate->triggerCommand = WCPRESSURES_CALLBACK_NONE;
    }
    else if (animUpdate->triggerCommand == WCPRESSURES_CALLBACK_RESET)
    {
        for (i = 0; i < WCPRESSURES_TRACKED_COUNT; i++)
        {
            state->objects[i] = 0;
        }
        /* sic: setup->x is stored to the Z slot and overwritten just below,
           so localPosX (obj+0xc) is left unrestored - faithful to retail */
        obj->anim.localPosZ = setup->base.posX;
        obj->anim.localPosY = setup->base.posY;
        obj->anim.localPosZ = setup->base.posZ;
        mainSetBits(setup->solvedBit, 0);
        animUpdate->triggerCommand = WCPRESSURES_CALLBACK_NONE;
    }

    return 0;
}

int wcpressures_getObjectTypeId(GameObject* obj)
{
    ObjAnimComponent* objAnim = (ObjAnimComponent*)obj;
    WCPressuresSetup* setup = (WCPressuresSetup*)obj->anim.placementData;
    int modelIndex = setup->modelIndex;
    int modelCount = objAnim->modelInstance->modelCount;

    if (modelIndex >= modelCount)
    {
        modelIndex = 0;
    }
    return (modelIndex << WCPRESSURES_RENDER_TYPE_SHIFT) | WCPRESSURES_RENDER_TYPE_BASE;
}

void wcpressures_free(GameObject* obj)
{
    ObjGroup_RemoveObject((int)obj, WCPRESSURES_OBJECT_GROUP);
}

void wcpressures_render(GameObject* obj, int p2, int p3, int p4, int p5, s8 visible)
{
    if (visible != 0)
    {
        objRenderModelAndHitVolumes((int)obj, p2, p3, p4, p5, lbl_803E6E00);
    }
}

void wcpressures_hitDetect(void)
{
}

void wcpressures_update(int obj)
{
    WCPressuresSetup* setup = *(WCPressuresSetup**)(obj + WCPRESSURES_OBJECT_SETUP_OFFSET);
    WCPressuresState* state = *(WCPressuresState**)(obj + WCPRESSURES_OBJECT_STATE_OFFSET);
    int i;
    int off;
    int j;
    f32 thr;

    if (setup->activateBit > 0 && mainGetBit(setup->activateBit) == 0)
    {
        logPrintf(sWCPressuresActivateFormat, setup->activateBit);
        return;
    }
    if ((state->pressTimer -= 1) < 0)
        state->pressTimer = 0;
    if ((s8) * (u8*)(*(int*)(obj + WCPRESSURES_HITLIST_OFFSET) + WCPRESSURES_HITLIST_COUNT_OFFSET) > 0)
    {
        for (i = 0, off = 0;
             i < (s8) * (u8*)(*(int*)(obj + WCPRESSURES_HITLIST_OFFSET) + WCPRESSURES_HITLIST_COUNT_OFFSET);
             off += 4, i++)
        {
            int ent = *(int*)(*(int*)(obj + WCPRESSURES_HITLIST_OFFSET) + off + WCPRESSURES_HITLIST_OBJECTS_OFFSET);
            if (((GameObject*)ent)->anim.localPosY - ((GameObject*)obj)->anim.localPosY >
                (f32)(u32)setup->triggerHeight)
            {
                WCPressuresState* s2 = *(WCPressuresState**)(obj + WCPRESSURES_OBJECT_STATE_OFFSET);
                int slot;

                for (j = 0; s2->objects[(u8)j] != NULL || (u8)j == WCPRESSURES_TRACKED_COUNT - 1; j++)
                    ;
                slot = (u8)j;
                s2->objects[slot] = (GameObject*)ent;
                s2->savedPos[slot].x = ((GameObject*)ent)->anim.localPosX;
                s2->savedPos[slot].z = ((GameObject*)ent)->anim.localPosZ;
            }
        }
    }
    {
        WCPressuresState* s2 = *(WCPressuresState**)(obj + WCPRESSURES_OBJECT_STATE_OFFSET);
        u8 found = 0;

        for (j = 0; (u8)j < WCPRESSURES_TRACKED_COUNT; j++)
        {
            int slot = (u8)j;
            GameObject* val = s2->objects[slot];
            if ((u32)val != 0)
            {
                if (s2->savedPos[slot].x == val->anim.localPosX && s2->savedPos[slot].z == val->anim.localPosZ)
                {
                    found = 1;
                }
                else
                {
                    s2->objects[slot] = 0;
                }
            }
        }
        if ((int)found != 0)
            state->pressTimer = WCPRESSURES_FOUND_TIMER;
    }
    thr = setup->y - (f32)(u32)setup->pressDepth;
    switch (state->mode)
    {
    case WCPRESSURES_MODE_RAISED:
        if (state->pressTimer != 0 && ((GameObject*)obj)->anim.localPosY >= thr)
        {
            Sfx_PlayFromObject(obj, SFXTRIG_dn_boar1_c_c7);
            state->mode = WCPRESSURES_MODE_LOWERING;
        }
        break;
    case WCPRESSURES_MODE_LOWERING:
        ((GameObject*)obj)->anim.localPosY = ((GameObject*)obj)->anim.localPosY - lbl_803E6E04 * timeDelta;
        if (((GameObject*)obj)->anim.localPosY < thr)
        {
            mainSetBits(setup->solvedBit, 1);
            state->mode = WCPRESSURES_MODE_PRESSED;
            ((GameObject*)obj)->anim.localPosY = thr;
        }
        break;
    case WCPRESSURES_MODE_PRESSED:
        if ((u32)mainGetBit(setup->solvedBit) == 0)
        {
            Sfx_PlayFromObject(obj, SFXTRIG_dn_boar1_c_c7);
            state->mode = WCPRESSURES_MODE_RISING;
        }
        break;
    case WCPRESSURES_MODE_RISING:
        ((GameObject*)obj)->anim.localPosY = lbl_803E6E04 * timeDelta + ((GameObject*)obj)->anim.localPosY;
        if (((GameObject*)obj)->anim.localPosY > setup->y)
        {
            ((GameObject*)obj)->anim.localPosY = setup->y;
            state->mode = WCPRESSURES_MODE_RAISED;
        }
        break;
    }
    {
        ObjTextureRuntimeSlot* tex =
            objFindTexture((GameObject*)obj, WCPRESSURES_TEXTURE_DEFAULT, WCPRESSURES_TEXTURE_DEFAULT);
        if (tex != 0)
        {
            tex->textureId =
                state->mode == WCPRESSURES_MODE_PRESSED ? WCPRESSURES_TEXTURE_PRESSED : WCPRESSURES_TEXTURE_DEFAULT;
            tex->textureId = tex->textureId << WCPRESSURES_TEXTURE_SHIFT;
        }
    }
}

void wcpressures_init(GameObject* obj, WCPressuresSetup* setup)
{
    ObjAnimComponent* objAnim = (ObjAnimComponent*)obj;
    WCPressuresState* state = (WCPressuresState*)obj->extra;
    s16 objType;
    u16 objFlags;
    s8 modelIndex;
    int i;

    objType = (s16)(setup->objectTypeHi << 8);
    obj->anim.rotX = objType;
    objFlags = obj->objectFlags | (WCPRESSURES_OBJFLAG_HIDDEN | WCPRESSURES_OBJFLAG_HITDETECT_DISABLED);
    obj->objectFlags = objFlags;
    modelIndex = setup->modelIndex;
    objAnim->bankIndex = modelIndex;
    if (objAnim->bankIndex >= objAnim->modelInstance->modelCount)
    {
        objAnim->bankIndex = 0;
    }

    if ((u32)mainGetBit(setup->solvedBit) != 0)
    {
        obj->anim.localPosY = setup->base.posY - setup->pressDepth;
        state->pressTimer = WCPRESSURES_SOLVED_TIMER;
        state->mode = WCPRESSURES_MODE_PRESSED;
    }

    ObjGroup_AddObject((int)obj, WCPRESSURES_OBJECT_GROUP);
    for (i = 0; i < WCPRESSURES_TRACKED_COUNT; i++)
    {
        state->objects[i] = 0;
    }
    obj->animEventCallback = wcpressures_SeqFn;
}

void wcpressures_release(void)
{
}

void wcpressures_initialise(void)
{
}

char sWCPressuresActivateFormat[] = " Avitvate %i ";

ObjectDescriptor gWCTrexStatuObjDescriptor = {0x00000000,
                                     0x00000000,
                                     0x00000000,
                                     0x00090000,
                                     (ObjectDescriptorCallback)wctrexstatu_initialise,
                                     (ObjectDescriptorCallback)wctrexstatu_release,
                                     0x00000000,
                                     (ObjectDescriptorCallback)wctrexstatu_init,
                                     (ObjectDescriptorCallback)wctrexstatu_update,
                                     (ObjectDescriptorCallback)wctrexstatu_hitDetect,
                                     (ObjectDescriptorCallback)wctrexstatu_render,
                                     (ObjectDescriptorCallback)wctrexstatu_free,
                                     (ObjectDescriptorCallback)wctrexstatu_getObjectTypeId,
                                     wctrexstatu_getExtraSize};
ObjectDescriptor gSunTempleObjDescriptor = {0x00000000,
                                   0x00000000,
                                   0x00000000,
                                   0x00090000,
                                   (ObjectDescriptorCallback)suntemple_initialise,
                                   (ObjectDescriptorCallback)suntemple_release,
                                   0x00000000,
                                   (ObjectDescriptorCallback)suntemple_init,
                                   (ObjectDescriptorCallback)suntemple_update,
                                   (ObjectDescriptorCallback)suntemple_hitDetect,
                                   (ObjectDescriptorCallback)suntemple_render,
                                   (ObjectDescriptorCallback)suntemple_free,
                                   (ObjectDescriptorCallback)suntemple_getObjectTypeId,
                                   suntemple_getExtraSize};
ObjectDescriptor gWCTempleObjDescriptor = {0x00000000,
                                  0x00000000,
                                  0x00000000,
                                  0x00090000,
                                  (ObjectDescriptorCallback)wctemple_initialise,
                                  (ObjectDescriptorCallback)wctemple_release,
                                  0x00000000,
                                  (ObjectDescriptorCallback)wctemple_init,
                                  (ObjectDescriptorCallback)wctemple_update,
                                  (ObjectDescriptorCallback)wctemple_hitDetect,
                                  (ObjectDescriptorCallback)wctemple_render,
                                  (ObjectDescriptorCallback)wctemple_free,
                                  (ObjectDescriptorCallback)wctemple_getObjectTypeId,
                                  wctemple_getExtraSize};
ObjectDescriptor dll_299 = {
    0,
    0,
    0,
    0x00090000,
    (ObjectDescriptorCallback)dll_299_initialise_nop,
    (ObjectDescriptorCallback)dll_299_release_nop,
    NULL,
    (ObjectDescriptorCallback)dll_299_init,
    (ObjectDescriptorCallback)dll_299_update,
    (ObjectDescriptorCallback)dll_299_hitDetect_nop,
    (ObjectDescriptorCallback)dll_299_render_nop,
    (ObjectDescriptorCallback)dll_299_free,
    (ObjectDescriptorCallback)dll_299_getObjectTypeId,
    dll_299_getExtraSize_ret_2,
};
ObjectDescriptor gWCApertureSObjDescriptor = {0x00000000,
                                     0x00000000,
                                     0x00000000,
                                     0x00090000,
                                     (ObjectDescriptorCallback)wcapertures_initialise,
                                     (ObjectDescriptorCallback)wcapertures_release,
                                     0x00000000,
                                     (ObjectDescriptorCallback)wcapertures_init,
                                     (ObjectDescriptorCallback)wcapertures_update,
                                     (ObjectDescriptorCallback)wcapertures_hitDetect,
                                     (ObjectDescriptorCallback)wcapertures_render,
                                     (ObjectDescriptorCallback)wcapertures_free,
                                     (ObjectDescriptorCallback)wcapertures_getObjectTypeId,
                                     wcapertures_getExtraSize};
