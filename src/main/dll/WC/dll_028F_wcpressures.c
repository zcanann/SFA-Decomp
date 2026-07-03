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
#include "main/dll/dll_80220608_shared.h"
#include "main/game_object.h"

#include "main/audio/sfx_ids.h"

#define WCPRESSURES_EXTRA_SIZE 0x7c
#define WCPRESSURES_TRACKED_COUNT 10
#define WCPRESSURES_OBJECT_GROUP 0x31
#define WCPRESSURES_RENDER_TYPE_BASE 0x400
#define WCPRESSURES_RENDER_TYPE_SHIFT 0xb

#define WCPRESSURES_SETUP_POS_X_OFFSET 0x08
#define WCPRESSURES_SETUP_POS_Y_OFFSET 0x0c
#define WCPRESSURES_SETUP_POS_Z_OFFSET 0x10
#define WCPRESSURES_SETUP_OBJECT_TYPE_HI_OFFSET 0x18
#define WCPRESSURES_SETUP_MODEL_INDEX_OFFSET 0x19
#define WCPRESSURES_SETUP_SOLVED_BIT_OFFSET 0x1a
#define WCPRESSURES_SETUP_PRESS_DEPTH_OFFSET 0x1c
#define WCPRESSURES_SETUP_TRIGGER_HEIGHT_OFFSET 0x1d
#define WCPRESSURES_SETUP_ACTIVATE_BIT_OFFSET 0x20

#define WCPRESSURES_STATE_PRESS_TIMER 0x00
#define WCPRESSURES_STATE_MODE 0x01
#define WCPRESSURES_STATE_OBJECTS 0x04
#define WCPRESSURES_STATE_SAVED_X 0x2c
#define WCPRESSURES_STATE_SAVED_Z 0x30

#define WCPRESSURES_MODE_RAISED 0
#define WCPRESSURES_MODE_RISING 1
#define WCPRESSURES_MODE_PRESSED 2
#define WCPRESSURES_MODE_LOWERING 3

#define WCPRESSURES_FOUND_TIMER 5
#define WCPRESSURES_SOLVED_TIMER 0x1e

#define WCPRESSURES_OBJECT_SETUP_OFFSET 0x4c
#define WCPRESSURES_OBJECT_Y_OFFSET 0x10
#define WCPRESSURES_OBJECT_Z_OFFSET 0x14
#define WCPRESSURES_OBJECT_STATE_OFFSET 0xb8

#define WCPRESSURES_CALLBACK_NONE 0
#define WCPRESSURES_CALLBACK_SNAPSHOT_TILES 1
#define WCPRESSURES_CALLBACK_RESET 2

#define WCPRESSURES_HITLIST_OFFSET 0x58
#define WCPRESSURES_HITLIST_OBJECTS_OFFSET 0x100
#define WCPRESSURES_HITLIST_COUNT_OFFSET 0x10f

#define WCPRESSURES_TEXTURE_DEFAULT 0
#define WCPRESSURES_TEXTURE_PRESSED 1
#define WCPRESSURES_TEXTURE_SHIFT 8

#define WCPRESSURES_OBJFLAG_HIDDEN 0x4000
#define WCPRESSURES_OBJFLAG_HITDETECT_DISABLED 0x2000


typedef struct WCPressuresSetup
{
    u8 pad00[WCPRESSURES_SETUP_POS_X_OFFSET];
    f32 x;
    f32 y;
    f32 z;
    u8 pad14[WCPRESSURES_SETUP_OBJECT_TYPE_HI_OFFSET - 0x14];
    u8 objectTypeHi;
    u8 modelIndex;
    s16 solvedBit;
    u8 pressDepth;
    u8 triggerHeight;
    u8 pad1E[WCPRESSURES_SETUP_ACTIVATE_BIT_OFFSET - 0x1e];
    s16 activateBit;
} WCPressuresSetup;

typedef struct WCPressuresSavedPos
{
    f32 x;
    f32 z;
} WCPressuresSavedPos;

typedef struct WCPressuresState
{
    s8 pressTimer;
    s8 mode;
    u8 pad02[2];
    GameObject* objects[WCPRESSURES_TRACKED_COUNT];
    WCPressuresSavedPos savedPos[WCPRESSURES_TRACKED_COUNT];
} WCPressuresState;

STATIC_ASSERT(sizeof(WCPressuresState) == WCPRESSURES_EXTRA_SIZE);
STATIC_ASSERT(offsetof(WCPressuresState, pressTimer) == WCPRESSURES_STATE_PRESS_TIMER);
STATIC_ASSERT(offsetof(WCPressuresState, mode) == WCPRESSURES_STATE_MODE);
STATIC_ASSERT(offsetof(WCPressuresState, objects) == WCPRESSURES_STATE_OBJECTS);
STATIC_ASSERT(offsetof(WCPressuresState, savedPos[0].x) == WCPRESSURES_STATE_SAVED_X);
STATIC_ASSERT(offsetof(WCPressuresState, savedPos[0].z) == WCPRESSURES_STATE_SAVED_Z);
STATIC_ASSERT(offsetof(WCPressuresSetup, x) == WCPRESSURES_SETUP_POS_X_OFFSET);
STATIC_ASSERT(offsetof(WCPressuresSetup, y) == WCPRESSURES_SETUP_POS_Y_OFFSET);
STATIC_ASSERT(offsetof(WCPressuresSetup, z) == WCPRESSURES_SETUP_POS_Z_OFFSET);
STATIC_ASSERT(offsetof(WCPressuresSetup, objectTypeHi) == WCPRESSURES_SETUP_OBJECT_TYPE_HI_OFFSET);
STATIC_ASSERT(offsetof(WCPressuresSetup, modelIndex) == WCPRESSURES_SETUP_MODEL_INDEX_OFFSET);
STATIC_ASSERT(offsetof(WCPressuresSetup, solvedBit) == WCPRESSURES_SETUP_SOLVED_BIT_OFFSET);
STATIC_ASSERT(offsetof(WCPressuresSetup, pressDepth) == WCPRESSURES_SETUP_PRESS_DEPTH_OFFSET);
STATIC_ASSERT(offsetof(WCPressuresSetup, triggerHeight) == WCPRESSURES_SETUP_TRIGGER_HEIGHT_OFFSET);
STATIC_ASSERT(offsetof(WCPressuresSetup, activateBit) == WCPRESSURES_SETUP_ACTIVATE_BIT_OFFSET);

int wcpressures_getExtraSize(void) { return WCPRESSURES_EXTRA_SIZE; }

int wcpressures_tileStateCallback(int obj, int unused, ObjAnimUpdateState* animUpdate)
{
    WCPressuresState* state = *(WCPressuresState**)(obj + WCPRESSURES_OBJECT_STATE_OFFSET);
    WCPressuresSetup* setup = *(WCPressuresSetup**)(obj + WCPRESSURES_OBJECT_SETUP_OFFSET);
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
        ((GameObject*)obj)->anim.localPosZ = setup->x;
        ((GameObject*)obj)->anim.localPosY = setup->y;
        ((GameObject*)obj)->anim.localPosZ = setup->z;
        GameBit_Set(setup->solvedBit, 0);
        animUpdate->triggerCommand = WCPRESSURES_CALLBACK_NONE;
    }

    return 0;
}

int wcpressures_getObjectTypeId(int obj)
{
    ObjAnimComponent* objAnim = (ObjAnimComponent*)obj;
    WCPressuresSetup* setup = *(WCPressuresSetup**)(obj + WCPRESSURES_OBJECT_SETUP_OFFSET);
    int modelIndex = setup->modelIndex;
    int modelCount = objAnim->modelInstance->modelCount;

    if (modelIndex >= modelCount)
    {
        modelIndex = 0;
    }
    return (modelIndex << WCPRESSURES_RENDER_TYPE_SHIFT) | WCPRESSURES_RENDER_TYPE_BASE;
}

void wcpressures_free(int obj) { ObjGroup_RemoveObject(obj, WCPRESSURES_OBJECT_GROUP); }

void wcpressures_render(int obj, int p2, int p3, int p4, int p5, s8 visible)
{
    if (visible != 0)
    {
        objRenderFn_8003b8f4(obj, p2, p3, p4, p5, lbl_803E6E00);
    }
}

void wcpressures_hitDetect(void)
{
}

void wcpressures_update(int obj)
{
    WCPressuresSetup* setup = *(WCPressuresSetup**)(obj + WCPRESSURES_OBJECT_SETUP_OFFSET);
    WCPressuresState* state = *(WCPressuresState**)(obj + WCPRESSURES_OBJECT_STATE_OFFSET);
    int j;
    int i;
    f32 thr;

    if (setup->activateBit > 0 &&
        GameBit_Get(setup->activateBit) == 0)
    {
        fn_80137948(sWCPressuresActivateFormat, setup->activateBit);
        return;
    }
    if ((state->pressTimer -= 1) < 0)
        state->pressTimer = 0;
    if ((s8) * (u8*)(*(int*)(obj + WCPRESSURES_HITLIST_OFFSET) + WCPRESSURES_HITLIST_COUNT_OFFSET) > 0)
    {
        for (i = 0;
             i < (s8) * (u8*)(*(int*)(obj + WCPRESSURES_HITLIST_OFFSET) + WCPRESSURES_HITLIST_COUNT_OFFSET);
             i++)
        {
            int ent = *(int*)(*(int*)(obj + WCPRESSURES_HITLIST_OFFSET) +
                i * 4 + WCPRESSURES_HITLIST_OBJECTS_OFFSET);
            if (((GameObject*)ent)->anim.localPosY - ((GameObject*)obj)->anim.localPosY >
                (f32)(u32)
                    setup->triggerHeight
            )
            {
                WCPressuresState* s2 = *(WCPressuresState**)(obj + WCPRESSURES_OBJECT_STATE_OFFSET);
                int slot;

                for (j = 0; s2->objects[(u8)j] != NULL ||
                     (u8)j == WCPRESSURES_TRACKED_COUNT - 1;
                     j++);
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
                if (s2->savedPos[slot].x == val->anim.localPosX &&
                    s2->savedPos[slot].z == val->anim.localPosZ)
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
    thr = setup->y - (f32)(u32)
    setup->pressDepth;
    switch (state->mode)
    {
    case WCPRESSURES_MODE_RAISED:
        if (state->pressTimer != 0 && ((GameObject*)obj)->anim.localPosY >= thr)
        {
            Sfx_PlayFromObject(obj, SFXsc_lockon2_on);
            state->mode = WCPRESSURES_MODE_LOWERING;
        }
        break;
    case WCPRESSURES_MODE_LOWERING:
        ((GameObject*)obj)->anim.localPosY = ((GameObject*)obj)->anim.localPosY - lbl_803E6E04 * timeDelta;
        if (((GameObject*)obj)->anim.localPosY < thr)
        {
            GameBit_Set(setup->solvedBit, 1);
            state->mode = WCPRESSURES_MODE_PRESSED;
            ((GameObject*)obj)->anim.localPosY = thr;
        }
        break;
    case WCPRESSURES_MODE_PRESSED:
        if ((u32)GameBit_Get(setup->solvedBit) == 0)
        {
            Sfx_PlayFromObject(obj, SFXsc_lockon2_on);
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
        ObjTextureRuntimeSlot *tex = objFindTexture((void *)obj, WCPRESSURES_TEXTURE_DEFAULT, WCPRESSURES_TEXTURE_DEFAULT);
        if (tex != 0) {
            tex->textureId = state->mode == WCPRESSURES_MODE_PRESSED ? WCPRESSURES_TEXTURE_PRESSED
                                                                      : WCPRESSURES_TEXTURE_DEFAULT;
            tex->textureId = tex->textureId << WCPRESSURES_TEXTURE_SHIFT;
        }
    }
}

void wcpressures_init(u8* obj, u8* setup)
{
    ObjAnimComponent* objAnim = (ObjAnimComponent*)obj;
    WCPressuresState* state = ((GameObject*)obj)->extra;
    WCPressuresSetup* setupData = (WCPressuresSetup*)setup;
    s16 objType;
    u16 objFlags;
    s8 modelIndex;
    int i;

    objType = (s16)(setupData->objectTypeHi << 8);
    ((GameObject*)obj)->anim.rotX = objType;
    objFlags = ((GameObject*)obj)->objectFlags | (WCPRESSURES_OBJFLAG_HIDDEN | WCPRESSURES_OBJFLAG_HITDETECT_DISABLED);
    ((GameObject*)obj)->objectFlags = objFlags;
    modelIndex = setupData->modelIndex;
    objAnim->bankIndex = modelIndex;
    if (objAnim->bankIndex >= objAnim->modelInstance->modelCount)
    {
        objAnim->bankIndex = 0;
    }

    if ((u32)GameBit_Get(setupData->solvedBit) != 0)
    {
        ((GameObject*)obj)->anim.localPosY = setupData->y - setupData->pressDepth;
        state->pressTimer = WCPRESSURES_SOLVED_TIMER;
        state->mode = WCPRESSURES_MODE_PRESSED;
    }

    ObjGroup_AddObject((int)obj, WCPRESSURES_OBJECT_GROUP);
    for (i = 0; i < WCPRESSURES_TRACKED_COUNT; i++)
    {
        state->objects[i] = 0;
    }
    ((GameObject*)obj)->animEventCallback = wcpressures_tileStateCallback;
}

void wcpressures_release(void)
{
}

void wcpressures_initialise(void)
{
}
