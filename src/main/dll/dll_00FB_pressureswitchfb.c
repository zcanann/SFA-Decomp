/*
 * pressureswitchfb (DLL 0x00FB) - a weight-activated pressure switch / floor
 * pad. While any tracked object (player, tricky, or seqId 0x754/0x6d) stands
 * far enough above the pad, the switch is held depressed: it slides on its
 * local Y toward the pressed target (CfGuardianState.targetPosY) at
 * velocityY * timeDelta, sets the placement's "pressed" game bit
 * (placement->pressedGameBit) and swaps to the pressed texture (id 0x100). When the
 * weight leaves it springs back up and clears the game bit.
 *
 * Up to PRESSURESWITCHFB_TRACKED_OBJECT_COUNT contacts are cached in the runtime
 * extra block; the animEventCallback (pressureswitchfb_updateStateMode) captures
 * or resets those slots on demand. canRelease / playerOnly / startPressed /
 * usePressedTexture behaviour comes from the seqId and placement flags. The pad
 * registers/unregisters in object group PRESSURESWITCHFB_REMOVE_GROUP_ID and can
 * drive a linked Tricky object via its vtable when not pressed.
 */
#include "main/game_object.h"
#include "main/dll/cfguardian_state.h"
#include "main/audio/sfx_ids.h"
#include "main/audio/sfx.h"
#include "main/gamebits.h"
#include "main/effect_interfaces.h"
#include "main/objtexture.h"
#include "main/objlib.h"
#include "main/gameplay_runtime.h"

#define PRESSURESWITCHFB_STATE_IDLE 0
#define PRESSURESWITCHFB_STATE_CAPTURE_POSITIONS 1
#define PRESSURESWITCHFB_STATE_RESET 2

#define PRESSURESWITCHFB_OBJFLAG_HIDDEN 0x4000
#define PRESSURESWITCHFB_OBJFLAG_HITDETECT_DISABLED 0x2000

#define PRESSURESWITCHFB_TRACKED_OBJECT_COUNT 10
#define PRESSURESWITCHFB_TRACKED_OBJECT_BATCH 5

#define PRESSURESWITCHFB_RUNTIME_TRACKED_OBJECTS_OFFSET 0x04
#define PRESSURESWITCHFB_RUNTIME_TRACKED_POSITIONS_OFFSET 0x2c
#define PRESSURESWITCHFB_RUNTIME_BASE_COORD_OFFSET 0x7c
#define PRESSURESWITCHFB_EXTRA_SIZE 0x88

#define PRESSURESWITCHFB_CONFIG_BASE_COORD_OFFSET 0x08
#define PRESSURESWITCHFB_CONFIG_RESET_COORD_OFFSET 0x10
#define PRESSURESWITCHFB_CONFIG_RAISED_GAMEBIT_OFFSET 0x1a

#define PRESSURESWITCHFB_STATE_MODE_OFFSET 0x80
#define PRESSURESWITCHFB_REMOVE_GROUP_ID 0x53

#define PRESSURESWITCHFB_OBJ_LINK_SNOWPR 0x019f
#define PRESSURESWITCHFB_OBJ_SH_PRESSURE 0x026c
#define PRESSURESWITCHFB_OBJ_LINK_UNDERW 0x0274
#define PRESSURESWITCHFB_OBJ_CC_PRESSURE 0x0545
#define PRESSURESWITCHFB_OBJ_WM_PRESSURE 0x077b

extern int ObjGroup_FindNearestObject();
extern void ObjGroup_AddObject();
extern f32 timeDelta;
extern int fn_80295C5C(void* player);
extern f32 Vec_distance(f32* a, f32* b);
extern f32 lbl_803E3758;
extern f32 lbl_803E375C;
extern f32 lbl_803E3760;
extern f32 lbl_803E3764;
extern f32 lbl_803E3768;
extern f32 lbl_803E3778;

int pressureswitchfb_updateStateMode(int obj, int unused, int stateParam)
{
    s16 objType;
    int config;
    u32 handle;
    u32 offset;
    int runtime;
    int trackedObjectSlot;
    u8 i;

    runtime = *(int*)&((GameObject*)obj)->extra;
    config = *(int*)&((GameObject*)obj)->anim.placementData;
    if (*(u8*)(stateParam + PRESSURESWITCHFB_STATE_MODE_OFFSET) ==
        PRESSURESWITCHFB_STATE_CAPTURE_POSITIONS)
    {
        for (i = 0; i < PRESSURESWITCHFB_TRACKED_OBJECT_COUNT; i++)
        {
            offset = (u32)i * 4 + PRESSURESWITCHFB_RUNTIME_TRACKED_OBJECTS_OFFSET;
            handle = *(u32*)(runtime + offset);
            if (handle != 0)
            {
                *(f32*)((trackedObjectSlot = runtime + (u32)i * 8) + PRESSURESWITCHFB_RUNTIME_TRACKED_POSITIONS_OFFSET) =
                    *(f32*)(handle + 0xc);
                *(f32*)(trackedObjectSlot + (PRESSURESWITCHFB_RUNTIME_TRACKED_POSITIONS_OFFSET + 4)) =
                    *(f32*)(*(int*)(runtime + offset) + 0x14);
            }
        }
        *(u8*)(stateParam + PRESSURESWITCHFB_STATE_MODE_OFFSET) =
            PRESSURESWITCHFB_STATE_IDLE;
    }
    else if (*(u8*)(stateParam + PRESSURESWITCHFB_STATE_MODE_OFFSET) ==
        PRESSURESWITCHFB_STATE_RESET)
    {
        for (i = 0; i < PRESSURESWITCHFB_TRACKED_OBJECT_COUNT;
             i += PRESSURESWITCHFB_TRACKED_OBJECT_BATCH)
        {
            *(int*)(trackedObjectSlot = runtime + i * 4 + PRESSURESWITCHFB_RUNTIME_TRACKED_OBJECTS_OFFSET) = 0;
            *(int*)(trackedObjectSlot + 0x4) = 0;
            *(int*)(trackedObjectSlot + 0x8) = 0;
            *(int*)(trackedObjectSlot + 0xc) = 0;
            *(int*)(trackedObjectSlot + 0x10) = 0;
        }
        ((GameObject*)obj)->anim.localPosZ = *(f32*)(config + PRESSURESWITCHFB_CONFIG_BASE_COORD_OFFSET);
        ((GameObject*)obj)->anim.localPosY = *(f32*)(runtime + PRESSURESWITCHFB_RUNTIME_BASE_COORD_OFFSET);
        ((GameObject*)obj)->anim.localPosZ = *(f32*)(config + PRESSURESWITCHFB_CONFIG_RESET_COORD_OFFSET);
        GameBit_Set(*(s16*)(config + PRESSURESWITCHFB_CONFIG_RAISED_GAMEBIT_OFFSET), 0);
        *(u8*)(stateParam + PRESSURESWITCHFB_STATE_MODE_OFFSET) =
            PRESSURESWITCHFB_STATE_IDLE;
    }
    objType = ((GameObject*)obj)->anim.seqId;
    if ((((objType != PRESSURESWITCHFB_OBJ_LINK_SNOWPR) &&
                (objType != PRESSURESWITCHFB_OBJ_SH_PRESSURE)) &&
            (objType != PRESSURESWITCHFB_OBJ_LINK_UNDERW)) &&
        (objType != PRESSURESWITCHFB_OBJ_CC_PRESSURE))
    {
        *(f32*)(runtime + PRESSURESWITCHFB_RUNTIME_BASE_COORD_OFFSET) = ((GameObject*)obj)->anim.localPosY;
    }
    return 0;
}

int pressureswitchfb_getExtraSize(void)
{
    return PRESSURESWITCHFB_EXTRA_SIZE;
}

void pressureswitchfb_free(int obj)
{
    ObjGroup_RemoveObject(obj,PRESSURESWITCHFB_REMOVE_GROUP_ID);
}

typedef void (*TrickyVtableFn)(int, int, int, int);

typedef struct PressureswitchfbState
{
    u8 pad0[0x68 - 0x0];
    s32 unk68;
    u8 pad6C[0x70 - 0x6C];
} PressureswitchfbState;

typedef struct PressureswitchfbPlacement
{
    u8 pad0[0x18 - 0x0];
    s16 unk18;
    s16 pressedGameBit;
    u8 pressDepth;
    u8 unk1D;
    u8 drivesTricky;
    u8 pad1F[0x20 - 0x1F];
    s16 enableGameBit;
    s16 unk22;
    s16 unk24;
    u8 pad26[0x28 - 0x26];
} PressureswitchfbPlacement;

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

typedef struct SwitchFlags
{
    u8 active : 1;
    u8 playerOnly : 1;
    u8 released : 1;
    u8 latched : 1;
    u8 rest : 4;
} SwitchFlags;

void pressureswitchfb_update(int obj)
{
    int found;
    int off;
    u32 other;
    int def;
    char* state;
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
    u32 o;
    f32 nearDist;
    FxArgs fx;

    def = *(int*)&((GameObject*)obj)->anim.placementData;
    state = ((GameObject*)obj)->extra;
    if ((((SwitchFlags*)(state + 0x84))->active) != 0)
    {
        if ((((SwitchFlags*)(state + 0x84))->released) == 0)
        {
            *(u8*)&((GameObject*)obj)->anim.resetHitboxMode |= INTERACT_FLAG_DISABLED;
        }
        else
        {
            *(u8*)&((GameObject*)obj)->anim.resetHitboxMode &= ~INTERACT_FLAG_DISABLED;
        }
    }
    else
    {
        *(u8*)&((GameObject*)obj)->anim.resetHitboxMode |= INTERACT_FLAG_DISABLED;
    }
    if ((((PressureswitchfbPlacement*)def)->enableGameBit == -1) || (GameBit_Get(((PressureswitchfbPlacement*)def)->enableGameBit) !=
        0))
    {
        if (--*state < 0)
        {
            *state = 0;
        }
        nearDist = lbl_803E3758;
        nearest = ObjGroup_FindNearestObject(5, obj, &nearDist);
        if (nearest != 0)
        {
            *state = 5;
        }
        if (*(s8*)(*(int*)(obj + 0x58) + 0x10f) > 0)
        {
            for (i = 0, off = 0; i < *(s8*)(*(int*)(obj + 0x58) + 0x10f); i++)
            {
                other = *(u32*)(*(int*)(obj + 0x58) + off + 0x100);
                if ((((GameObject*)other)->anim.classId == 1) || (((GameObject*)other)->anim.classId == 2) ||
                    (((GameObject*)other)->anim.seqId == 0x754) || (((GameObject*)other)->anim.seqId == 0x6d))
                {
                    isTarget = 1;
                }
                else
                {
                    isTarget = 0;
                }
                if (isTarget && (other != nearest))
                {
                    if (((GameObject*)other)->anim.localPosY - ((GameObject*)obj)->anim.localPosY > (f32)(u32) * (u8*)(
                        def + 0x1d))
                    {
                        tmp = *(int*)&((GameObject*)obj)->extra;
                        j = 0;
                        if ((((SwitchFlags*)(tmp + 0x84))->playerOnly) != 0)
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
                    skip_insert: ;
                    }
                }
                off += 4;
            }
        }
        slots2 = *(volatile int*)&((GameObject*)obj)->extra;
        found = 0;
        for (j2 = 0; j2 < PRESSURESWITCHFB_TRACKED_OBJECT_COUNT; j2++)
        {
            o = *(u32*)(slots2 + j2 * 4 + 4);
            if (o != 0)
            {
                base2 = slots2 + j2 * 8;
                if ((*(f32*)(base2 + 0x2c) == ((GameObject*)o)->anim.localPosX) &&
                    (*(f32*)(base2 + 0x30) == ((GameObject*)o)->anim.localPosZ))
                {
                    found = 1;
                }
                else
                {
                    *(int*)(slots2 + j2 * 4 + 4) = 0;
                }
            }
        }
        if (found & 0xff)
        {
            *state = 5;
        }
        i = 0;
        if ((*state != 0) && ((((SwitchFlags*)(state + 0x84))->latched) == 0))
        {
            if ((((SwitchFlags*)(state + 0x84))->active) != 0)
            {
                if (fn_80295C5C(Obj_GetPlayerObject()) != 0)
                {
                    ((SwitchFlags*)(state + 0x84))->released = 0;
                }
            }
            if ((((SwitchFlags*)(state + 0x84))->released) == 0)
            {
                target = ((CfGuardianState*)state)->targetPosY - (f32)(u32) * (u8*)(def + 0x1c);
                cur = ((GameObject*)obj)->anim.localPosY;
                if (cur < target)
                {
                    ((GameObject*)obj)->anim.localPosY = ((CfGuardianState*)state)->velocityY * timeDelta + cur;
                    if (((GameObject*)obj)->anim.localPosY > target)
                    {
                        ((GameObject*)obj)->anim.localPosY = target;
                    }
                    GameBit_Set(((PressureswitchfbPlacement*)def)->pressedGameBit, 1);
                    if ((((SwitchFlags*)(state + 0x84))->active) != 0)
                    {
                        tex = objFindTexture((int*)obj, 0, 0);
                        if (tex != NULL)
                        {
                            tex->textureId = 0x100;
                        }
                        ((SwitchFlags*)(state + 0x84))->latched = 1;
                    }
                }
                else
                {
                    ((GameObject*)obj)->anim.localPosY = -(((CfGuardianState*)state)->velocityY * timeDelta - cur);
                    if (((GameObject*)obj)->anim.localPosY < target)
                    {
                        ((GameObject*)obj)->anim.localPosY = target;
                        GameBit_Set(((PressureswitchfbPlacement*)def)->pressedGameBit, 1);
                        if ((((SwitchFlags*)(state + 0x84))->active) != 0)
                        {
                            tex = objFindTexture((int*)obj, 0, 0);
                            if (tex != NULL)
                            {
                                tex->textureId = 0x100;
                            }
                            ((SwitchFlags*)(state + 0x84))->latched = 1;
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
                ((GameObject*)obj)->anim.localPosY = ((CfGuardianState*)state)->velocityY * timeDelta + ((GameObject*)
                    obj)->anim.localPosY;
                if (((GameObject*)obj)->anim.localPosY > ((CfGuardianState*)state)->targetPosY)
                {
                    ((GameObject*)obj)->anim.localPosY = ((CfGuardianState*)state)->targetPosY;
                }
                else
                {
                    i = 1;
                }
            }
        }
        else
        {
            if ((((SwitchFlags*)(state + 0x84))->latched) == 0)
            {
                cur = ((GameObject*)obj)->anim.localPosY;
                if (cur < ((CfGuardianState*)state)->targetPosY)
                {
                    ((GameObject*)obj)->anim.localPosY = ((CfGuardianState*)state)->velocityY * timeDelta + cur;
                    if (((GameObject*)obj)->anim.localPosY > ((CfGuardianState*)state)->targetPosY)
                    {
                        ((GameObject*)obj)->anim.localPosY = ((CfGuardianState*)state)->targetPosY;
                        GameBit_Set(((PressureswitchfbPlacement*)def)->pressedGameBit, 0);
                    }
                    else
                    {
                        i = 1;
                    }
                }
            }
            else
            {
                if (GameBit_Get(((PressureswitchfbPlacement*)def)->pressedGameBit) == 0)
                {
                    tex = objFindTexture((int*)obj, 0, 0);
                    if (tex != NULL)
                    {
                        tex->textureId = 0;
                    }
                    ((SwitchFlags*)(state + 0x84))->latched = 0;
                    ((SwitchFlags*)(state + 0x84))->released = 1;
                }
            }
        }
        if (((((GameObject*)obj)->objectFlags & OBJECT_OBJFLAG_RENDERED) != 0) && ((((SwitchFlags*)(state + 0x84))->latched) == 0) &&
            ((((SwitchFlags*)(state + 0x84))->active) != 0))
        {
            tmp = (int)Obj_GetPlayerObject();
            if (Vec_distance(&((GameObject*)obj)->anim.worldPosX, (f32*)(tmp + 0x18)) < lbl_803E375C)
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
                    (*gPartfxInterface)->spawnObject((void*)obj, 0x7c3, &fx, 2, -1, NULL);
                    tmp++;
                }
                while (tmp < 3);
            }
        }
        if ((s8)i != 0)
        {
            Sfx_PlayFromObject(obj, SFXms_baddie_beamin);
        }
        else
        {
            Sfx_StopObjectChannel(obj, 8);
        }
        if (((((PressureswitchfbPlacement*)def)->drivesTricky != 0) && ((char*)(tmp = (int)getTrickyObject()) != NULL)) &&
            (GameBit_Get(((PressureswitchfbPlacement*)def)->pressedGameBit) == 0))
        {
            *(u8*)&((GameObject*)obj)->anim.resetHitboxMode &= ~INTERACT_FLAG_DISABLED;
            if ((*(u8*)&((GameObject*)obj)->anim.resetHitboxMode & INTERACT_FLAG_IN_RANGE) != 0)
            {
                (*(TrickyVtableFn*)(*(int*)(((PressureswitchfbState*)tmp)->unk68) + 0x28))(tmp, obj, 1, 3);
            }
        }
    }
}

typedef struct PressureSwitchFbFlags
{
    u8 usePressedTexture : 1;
    u8 startPressed : 1;
    u8 canRelease : 1;
    u8 autoPress : 1;
    u8 unused4 : 1;
    u8 unused5 : 1;
    u8 unused6 : 1;
    u8 unused7 : 1;
} PressureSwitchFbFlags;

void pressureswitchfb_init(u8* obj, u8* params)
{
    ObjAnimComponent* objAnim;
    u8* sub;
    ObjTextureRuntimeSlot* tex;
    f32 defaultOffset;
    PressureSwitchFbFlags* flags;

    objAnim = (ObjAnimComponent*)obj;
    sub = ((GameObject*)obj)->extra;
    flags = (PressureSwitchFbFlags*)(sub + 0x84);
    ((GameObject*)obj)->anim.rotX = (s16)(params[0x18] << 8);
    ((GameObject*)obj)->objectFlags = (u16)(((GameObject*)obj)->objectFlags | (PRESSURESWITCHFB_OBJFLAG_HIDDEN | PRESSURESWITCHFB_OBJFLAG_HITDETECT_DISABLED));
    objAnim->bankIndex = params[0x19];
    if (objAnim->bankIndex >= objAnim->modelInstance->modelCount)
    {
        objAnim->bankIndex = 0;
    }
    defaultOffset = lbl_803E3778;
    ((CfGuardianState*)sub)->velocityY = defaultOffset;
    if (((GameObject*)obj)->anim.seqId == PRESSURESWITCHFB_OBJ_WM_PRESSURE)
    {
        flags->usePressedTexture = 1;
        flags->startPressed = 1;
        flags->canRelease = 1;
        ((CfGuardianState*)sub)->velocityY = defaultOffset;
    }
    ((CfGuardianState*)sub)->targetPosY = *(f32*)(params + 0xc);
    if (GameBit_Get(((PressureswitchfbPlacement*)params)->pressedGameBit) != 0)
    {
        s16 model;
        ((GameObject*)obj)->anim.localPosY = ((CfGuardianState*)sub)->targetPosY - (f32)(u32)
        ((PressureswitchfbPlacement*)params)->pressDepth;
        sub[0] = 0x1e;
        flags->canRelease = 0;
        model = ((GameObject*)obj)->anim.seqId;
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
            tex = objFindTexture((int*)obj, 0, 0);
            if (tex != NULL)
            {
                tex->textureId = 0x100;
            }
        }
    }
    ObjGroup_AddObject(obj, PRESSURESWITCHFB_REMOVE_GROUP_ID);
    ((CfGuardianState*)sub)->unk4 = 0;
    ((CfGuardianState*)sub)->unk8 = 0;
    ((CfGuardianState*)sub)->unkC = 0;
    ((CfGuardianState*)sub)->unk10 = 0;
    ((CfGuardianState*)sub)->unk14 = 0;
    ((CfGuardianState*)sub)->unk18 = 0;
    ((CfGuardianState*)sub)->unk1C = 0;
    ((CfGuardianState*)sub)->unk20 = 0;
    ((CfGuardianState*)sub)->unk24 = 0;
    ((CfGuardianState*)sub)->unk28 = 0;
    ((GameObject*)obj)->animEventCallback = pressureswitchfb_updateStateMode;
}
