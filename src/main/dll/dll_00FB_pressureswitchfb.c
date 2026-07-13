/*
 * pressureswitchfb (DLL 0x00FB) - a weight-activated pressure switch / floor
 * pad. While any tracked object (player, tricky, or seqId 0x754/0x6d) stands
 * far enough above the pad, the switch is held depressed: it slides on its
 * local Y toward the pressed target (PressureSwitchFbState.targetPosY) at
 * velocityY * timeDelta, sets the placement's "pressed" game bit
 * (placement->pressedGameBit) and swaps to the pressed texture (id 0x100). When the
 * weight leaves it springs back up and clears the game bit.
 *
 * Up to PRESSURESWITCHFB_TRACKED_OBJECT_COUNT contacts are cached in the runtime
 * extra block; the animEventCallback (PressureSwitchFB_SeqFn) captures
 * or resets those slots on demand. canRelease / playerOnly / startPressed /
 * usePressedTexture behaviour comes from the seqId and placement flags. The pad
 * registers/unregisters in object group PRESSURESWITCHFB_REMOVE_GROUP_ID and can
 * drive a linked Tricky object via its vtable when not pressed.
 */
#include "main/game_object.h"
#include "main/object.h"
#include "main/audio/sfx_ids.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/audio/sfx.h"
#include "main/gamebits.h"
#include "main/effect_interfaces.h"
#include "main/objtexture.h"
#include "main/obj_group.h"
#include "main/gameplay_runtime.h"
#include "main/frame_timing.h"
#include "main/dll/dll_00FB_pressureswitchfb.h"

#define PRESSURESWITCHFB_PARTFX                  0x7c3
#define PRESSURESWITCHFB_STATE_IDLE              0
#define PRESSURESWITCHFB_STATE_CAPTURE_POSITIONS 1
#define PRESSURESWITCHFB_STATE_RESET             2

#define PRESSURESWITCHFB_OBJFLAG_HIDDEN             0x4000
#define PRESSURESWITCHFB_OBJFLAG_HITDETECT_DISABLED 0x2000

#define PRESSURESWITCHFB_TRACKED_OBJECT_COUNT 10
#define PRESSURESWITCHFB_TRACKED_OBJECT_BATCH 5

/* anim.seqIds of objects this pad reacts to (docblock: "any tracked object
 * (player, tricky, or seqId 0x754/0x6d) stands on it"). */
#define PRESSURESWITCHFB_TRACKED_SEQID_A 0x754
#define PRESSURESWITCHFB_TRACKED_SEQID_B 0x6d

#define PRESSURESWITCHFB_RUNTIME_TRACKED_OBJECTS_OFFSET   0x04
#define PRESSURESWITCHFB_RUNTIME_TRACKED_POSITIONS_OFFSET 0x2c
#define PRESSURESWITCHFB_RUNTIME_BASE_COORD_OFFSET        0x7c
#define PRESSURESWITCHFB_EXTRA_SIZE                       0x88

#define PRESSURESWITCHFB_CONFIG_BASE_COORD_OFFSET     0x08
#define PRESSURESWITCHFB_CONFIG_RESET_COORD_OFFSET    0x10
#define PRESSURESWITCHFB_CONFIG_RAISED_GAMEBIT_OFFSET 0x1a

#define PRESSURESWITCHFB_STATE_MODE_OFFSET 0x80
#define PRESSURESWITCHFB_REMOVE_GROUP_ID   0x53
#define PRESSURESWITCHFB_TARGET_OBJGROUP   5

#define PRESSURESWITCHFB_PRESSED_TEXTURE_ID 0x100

#define PRESSURESWITCHFB_OBJ_LINK_SNOWPR 0x019f
#define PRESSURESWITCHFB_OBJ_SH_PRESSURE 0x026c
#define PRESSURESWITCHFB_OBJ_LINK_UNDERW 0x0274
#define PRESSURESWITCHFB_OBJ_CC_PRESSURE 0x0545
#define PRESSURESWITCHFB_OBJ_WM_PRESSURE 0x077b

extern int fn_80295C5C(GameObject* player);
extern f32 lbl_803E3758;
extern f32 lbl_803E375C;
extern f32 lbl_803E3760;
extern f32 lbl_803E3764;
extern f32 lbl_803E3768;
extern f32 lbl_803E3778;

int PressureSwitchFB_SeqFn(GameObject* obj, int unused, int stateParam)
{
    s16 objType;
    int config;
    u32 handle;
    u32 offset;
    int runtime;
    int trackedObjectSlot;
    u8 i;

    runtime = *(int*)&obj->extra;
    config = *(int*)&obj->anim.placementData;
    if (*(u8*)(stateParam + PRESSURESWITCHFB_STATE_MODE_OFFSET) == PRESSURESWITCHFB_STATE_CAPTURE_POSITIONS)
    {
        for (i = 0; i < PRESSURESWITCHFB_TRACKED_OBJECT_COUNT; i++)
        {
            offset = (u32)i * 4 + PRESSURESWITCHFB_RUNTIME_TRACKED_OBJECTS_OFFSET;
            handle = *(u32*)(runtime + offset);
            if (handle != 0)
            {
                *(f32*)((trackedObjectSlot = runtime + (u32)i * 8) +
                        PRESSURESWITCHFB_RUNTIME_TRACKED_POSITIONS_OFFSET) = ((GameObject*)handle)->anim.localPosX;
                *(f32*)(trackedObjectSlot + (PRESSURESWITCHFB_RUNTIME_TRACKED_POSITIONS_OFFSET + 4)) =
                    ((GameObject*)*(int*)(runtime + offset))->anim.localPosZ;
            }
        }
        *(u8*)(stateParam + PRESSURESWITCHFB_STATE_MODE_OFFSET) = PRESSURESWITCHFB_STATE_IDLE;
    }
    else if (*(u8*)(stateParam + PRESSURESWITCHFB_STATE_MODE_OFFSET) == PRESSURESWITCHFB_STATE_RESET)
    {
        for (i = 0; i < PRESSURESWITCHFB_TRACKED_OBJECT_COUNT; i += PRESSURESWITCHFB_TRACKED_OBJECT_BATCH)
        {
            *(int*)(trackedObjectSlot = runtime + i * 4 + PRESSURESWITCHFB_RUNTIME_TRACKED_OBJECTS_OFFSET) = 0;
            *(int*)(trackedObjectSlot + 0x4) = 0;
            *(int*)(trackedObjectSlot + 0x8) = 0;
            *(int*)(trackedObjectSlot + 0xc) = 0;
            *(int*)(trackedObjectSlot + 0x10) = 0;
        }
        obj->anim.localPosZ = *(f32*)(config + PRESSURESWITCHFB_CONFIG_BASE_COORD_OFFSET);
        obj->anim.localPosY = *(f32*)(runtime + PRESSURESWITCHFB_RUNTIME_BASE_COORD_OFFSET);
        obj->anim.localPosZ = *(f32*)(config + PRESSURESWITCHFB_CONFIG_RESET_COORD_OFFSET);
        mainSetBits(*(s16*)(config + PRESSURESWITCHFB_CONFIG_RAISED_GAMEBIT_OFFSET), 0);
        *(u8*)(stateParam + PRESSURESWITCHFB_STATE_MODE_OFFSET) = PRESSURESWITCHFB_STATE_IDLE;
    }
    objType = obj->anim.seqId;
    if ((((objType != PRESSURESWITCHFB_OBJ_LINK_SNOWPR) && (objType != PRESSURESWITCHFB_OBJ_SH_PRESSURE)) &&
         (objType != PRESSURESWITCHFB_OBJ_LINK_UNDERW)) &&
        (objType != PRESSURESWITCHFB_OBJ_CC_PRESSURE))
    {
        *(f32*)(runtime + PRESSURESWITCHFB_RUNTIME_BASE_COORD_OFFSET) = obj->anim.localPosY;
    }
    return 0;
}

int PressureSwitchFB_getExtraSize(void)
{
    return PRESSURESWITCHFB_EXTRA_SIZE;
}

void PressureSwitchFB_free(GameObject* obj)
{
    ObjGroup_RemoveObject((int)obj, PRESSURESWITCHFB_REMOVE_GROUP_ID);
}

typedef void (*TrickyVtableFn)(GameObject* tricky, GameObject* switchObj, int enabled, int mode);

typedef struct FxArgs
{
    u8 pad[4];
    u16 type;
    u16 arg;
    f32 w;
    f32 x;
    f32 y;
    f32 z;
} FxArgs;

static inline int pfb_scanTrackedSlots(int slots2, u8 j2, int found, int zid)
{
    u32 otherObj;
    int base2;
    for (; j2 < PRESSURESWITCHFB_TRACKED_OBJECT_COUNT; j2++)
    {
        otherObj = *(u32*)(slots2 + j2 * 4 + 4);
        if (otherObj != 0)
        {
            base2 = slots2 + j2 * 8;
            if ((*(f32*)(base2 + 0x2c) == ((GameObject*)otherObj)->anim.localPosX) &&
                (*(f32*)(base2 + 0x30) == ((GameObject*)otherObj)->anim.localPosZ))
            {
                found = 1;
            }
            else
            {
                *(int*)(slots2 + j2 * 4 + 4) = zid;
            }
        }
    }
    return found;
}

void PressureSwitchFB_update(GameObject* obj)
{
    int found;
    int off;
    u32 other;
    PressureswitchfbPlacement* def;
    PressureSwitchFbState* state;
    int i;
    int tmp;
    u8 j;
    int isTarget;
    int base;
    ObjTextureRuntimeSlot* tex;
    f32 cur;
    f32 target;
    u8 j2;
    u32 nearest;
    int slots2;
    int base2;
    u32 otherObj;
    GameObject* tricky;
    f32 nearDist;
    FxArgs fx;

    def = (PressureswitchfbPlacement*)obj->anim.placementData;
    state = obj->extra;
    if (state->flags.update.active != 0)
    {
        if (state->flags.update.released == 0)
        {
            *(u8*)&obj->anim.resetHitboxMode |= INTERACT_FLAG_DISABLED;
        }
        else
        {
            *(u8*)&obj->anim.resetHitboxMode &= ~INTERACT_FLAG_DISABLED;
        }
    }
    else
    {
        *(u8*)&obj->anim.resetHitboxMode |= INTERACT_FLAG_DISABLED;
    }
    if ((def->enableGameBit == -1) ||
        (mainGetBit(def->enableGameBit) != 0))
    {
        if (--state->contactTimer < 0)
        {
            state->contactTimer = 0;
        }
        nearDist = lbl_803E3758;
        nearest = ObjGroup_FindNearestObject(PRESSURESWITCHFB_TARGET_OBJGROUP, (int)obj, &nearDist);
        if (nearest != 0)
        {
            state->contactTimer = 5;
        }
        if (*(s8*)(*(int*)((u8*)obj + 0x58) + 0x10f) > 0)
        {
            for (i = 0, off = 0; i < *(s8*)(*(int*)((u8*)obj + 0x58) + 0x10f); i++)
            {
                other = *(u32*)(*(int*)((u8*)obj + 0x58) + off + 0x100);
                if ((((GameObject*)other)->anim.classId == 1) || (((GameObject*)other)->anim.classId == 2) ||
                    (((GameObject*)other)->anim.seqId == PRESSURESWITCHFB_TRACKED_SEQID_A) ||
                    (((GameObject*)other)->anim.seqId == PRESSURESWITCHFB_TRACKED_SEQID_B))
                {
                    isTarget = 1;
                }
                else
                {
                    isTarget = 0;
                }
                if (isTarget && (other != nearest))
                {
                    if (((GameObject*)other)->anim.localPosY - obj->anim.localPosY >
                        (f32)(u32)def->unk1D)
                    {
                        tmp = *(int*)&obj->extra;
                        j = 0;
                        if (state->flags.update.playerOnly != 0)
                        {
                            if (other == (u32)Obj_GetPlayerObject())
                                goto do_insert;
                            else
                                goto skip_insert;
                        }
                    do_insert:
                        while ((*(u32*)(tmp + j * 4 + 4) != 0) && (j != 9))
                        {
                            j++;
                        }
                        *(u32*)(tmp + j * 4 + 4) = other;
                        *(f32*)((base = tmp + j * 8) + 0x2c) = ((GameObject*)other)->anim.localPosX;
                        *(f32*)(base + 0x30) = ((GameObject*)other)->anim.localPosZ;
                    skip_insert:;
                    }
                }
                off += 4;
            }
        }
        slots2 = *(volatile int*)&obj->extra;
        found = pfb_scanTrackedSlots(slots2, 0, 0, 0);
        if (found & 0xff)
        {
            state->contactTimer = 5;
        }
        i = 0;
        if ((state->contactTimer != 0) && (state->flags.update.latched == 0))
        {
            if (state->flags.update.active != 0)
            {
                if (fn_80295C5C((GameObject*)(Obj_GetPlayerObject())) != 0)
                {
                    state->flags.update.released = 0;
                }
            }
            if (state->flags.update.released == 0)
            {
                target =
                    state->targetPosY - (f32)(u32)def->pressDepth;
                cur = obj->anim.localPosY;
                if (cur < target)
                {
                    obj->anim.localPosY = state->velocityY * timeDelta + cur;
                    if (obj->anim.localPosY > target)
                    {
                        obj->anim.localPosY = target;
                    }
                    mainSetBits(def->pressedGameBit, 1);
                    if (state->flags.update.active != 0)
                    {
                        tex = objFindTexture(obj, 0, 0);
                        if (tex != NULL)
                        {
                            tex->textureId = PRESSURESWITCHFB_PRESSED_TEXTURE_ID;
                        }
                        state->flags.update.latched = 1;
                    }
                }
                else
                {
                    obj->anim.localPosY = -(state->velocityY * timeDelta - cur);
                    if (obj->anim.localPosY < target)
                    {
                        obj->anim.localPosY = target;
                        mainSetBits(def->pressedGameBit, 1);
                        if (state->flags.update.active != 0)
                        {
                            tex = objFindTexture(obj, 0, 0);
                            if (tex != NULL)
                            {
                                tex->textureId = PRESSURESWITCHFB_PRESSED_TEXTURE_ID;
                            }
                            state->flags.update.latched = 1;
                        }
                    }
                    else
                    {
                        i = 1;
                    }
                }
            }
            else
            {
                obj->anim.localPosY =
                    state->velocityY * timeDelta + obj->anim.localPosY;
                if (obj->anim.localPosY > state->targetPosY)
                {
                    obj->anim.localPosY = state->targetPosY;
                }
                else
                {
                    i = 1;
                }
            }
        }
        else
        {
            if (state->flags.update.latched == 0)
            {
                cur = obj->anim.localPosY;
                if (cur < state->targetPosY)
                {
                    obj->anim.localPosY = state->velocityY * timeDelta + cur;
                    if (obj->anim.localPosY > state->targetPosY)
                    {
                        obj->anim.localPosY = state->targetPosY;
                        mainSetBits(def->pressedGameBit, 0);
                    }
                    else
                    {
                        i = 1;
                    }
                }
            }
            else
            {
                if (mainGetBit(def->pressedGameBit) == 0)
                {
                    tex = objFindTexture(obj, 0, 0);
                    if (tex != NULL)
                    {
                        tex->textureId = 0;
                    }
                    state->flags.update.latched = 0;
                    state->flags.update.released = 1;
                }
            }
        }
        if (((obj->objectFlags & OBJECT_OBJFLAG_RENDERED) != 0) &&
            (state->flags.update.latched == 0) && (state->flags.update.active != 0))
        {
            tmp = (int)Obj_GetPlayerObject();
            if (Vec_distance(&obj->anim.worldPosX, &((GameObject*)tmp)->anim.worldPosX) < lbl_803E375C)
            {
                fx.x = lbl_803E3760;
                fx.y = lbl_803E3764;
                fx.z = lbl_803E3760;
                fx.w = lbl_803E3768;
                fx.arg = 0x12;
                fx.type = 10;
                tmp = 0;
                do
                {
                    (*gPartfxInterface)->spawnObject((void*)obj, PRESSURESWITCHFB_PARTFX, &fx, 2, -1, NULL);
                    tmp++;
                } while (tmp < 3);
            }
        }
        if ((s8)i != 0)
        {
            Sfx_PlayFromObject((u32)obj, SFXTRIG_en_firlp6);
        }
        else
        {
            Sfx_StopObjectChannel((u32)obj, 8);
        }
        if (((def->drivesTricky != 0) &&
             ((tricky = (GameObject*)getTrickyObject()) != NULL)) &&
            (mainGetBit(def->pressedGameBit) == 0))
        {
            *(u8*)&obj->anim.resetHitboxMode &= ~INTERACT_FLAG_DISABLED;
            if ((*(u8*)&obj->anim.resetHitboxMode & INTERACT_FLAG_IN_RANGE) != 0)
            {
                (*(TrickyVtableFn*)((u8*)*tricky->anim.dll + 0x28))(tricky, obj, 1, 3);
            }
        }
    }
}

void PressureSwitchFB_init(GameObject* obj, PressureswitchfbPlacement* params)
{
    ObjAnimComponent* objAnim;
    PressureSwitchFbState* state;
    ObjTextureRuntimeSlot* tex;
    f32 defaultOffset;
    PressureSwitchFbFlags* flags;

    objAnim = (ObjAnimComponent*)obj;
    state = obj->extra;
    flags = &state->flags.init;
    obj->anim.rotX = (s16)(params->initialYaw << 8);
    obj->objectFlags =
        (u16)(obj->objectFlags | (PRESSURESWITCHFB_OBJFLAG_HIDDEN | PRESSURESWITCHFB_OBJFLAG_HITDETECT_DISABLED));
    objAnim->bankIndex = params->modelBankIndex;
    if (objAnim->bankIndex >= objAnim->modelInstance->modelCount)
    {
        objAnim->bankIndex = 0;
    }
    defaultOffset = lbl_803E3778;
    state->velocityY = defaultOffset;
    if (obj->anim.seqId == PRESSURESWITCHFB_OBJ_WM_PRESSURE)
    {
        flags->usePressedTexture = 1;
        flags->startPressed = 1;
        flags->canRelease = 1;
        state->velocityY = defaultOffset;
    }
    state->targetPosY = params->base.posY;
    if (mainGetBit(params->pressedGameBit) != 0)
    {
        s16 model;
        obj->anim.localPosY = state->targetPosY - (f32)(u32)params->pressDepth;
        state->contactTimer = 0x1e;
        flags->canRelease = 0;
        model = obj->anim.seqId;
        if (model != PRESSURESWITCHFB_OBJ_LINK_SNOWPR)
        {
            if (model != PRESSURESWITCHFB_OBJ_SH_PRESSURE)
            {
                if (model != PRESSURESWITCHFB_OBJ_LINK_UNDERW)
                {
                    if (model != PRESSURESWITCHFB_OBJ_CC_PRESSURE)
                    {
                        flags->autoPress = 1;
                    }
                }
            }
        }
        if (flags->usePressedTexture)
        {
            tex = objFindTexture(obj, 0, 0);
            if (tex != NULL)
            {
                tex->textureId = PRESSURESWITCHFB_PRESSED_TEXTURE_ID;
            }
        }
    }
    ObjGroup_AddObject((int)obj, PRESSURESWITCHFB_REMOVE_GROUP_ID);
    state->trackedObjects[0] = NULL;
    state->trackedObjects[1] = NULL;
    state->trackedObjects[2] = NULL;
    state->trackedObjects[3] = NULL;
    state->trackedObjects[4] = NULL;
    state->trackedObjects[5] = NULL;
    state->trackedObjects[6] = NULL;
    state->trackedObjects[7] = NULL;
    state->trackedObjects[8] = NULL;
    state->trackedObjects[9] = NULL;
    obj->animEventCallback = PressureSwitchFB_SeqFn;
}
