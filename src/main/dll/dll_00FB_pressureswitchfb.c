#include "main/game_object.h"

extern undefined8 ObjGroup_RemoveObject();

#define PRESSURESWITCHFB_STATE_IDLE 0
#define PRESSURESWITCHFB_STATE_CAPTURE_POSITIONS 1
#define PRESSURESWITCHFB_STATE_RESET 2

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

/*
 * --INFO--
 *
 * Function: pressureswitchfb_updateStateMode
 * EN v1.0 Address: 0x8017AC2C
 * EN v1.0 Size: 348b
 * EN v1.1 Address: 0x8017AC40
 * EN v1.1 Size: 388b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 pressureswitchfb_updateStateMode(int obj, undefined4 param_2, int stateParam)
{
    extern void GameBit_Set(int eventId, int value); /* #57 */
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
                *(f32*)(runtime + (u32)i * 8 + PRESSURESWITCHFB_RUNTIME_TRACKED_POSITIONS_OFFSET) =
                    *(f32*)(handle + 0xc);
                *(f32*)(runtime + (u32)i * 8 + (PRESSURESWITCHFB_RUNTIME_TRACKED_POSITIONS_OFFSET + 4)) =
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
            trackedObjectSlot = runtime + (u32)i * 4 + PRESSURESWITCHFB_RUNTIME_TRACKED_OBJECTS_OFFSET;
            *(undefined4*)(trackedObjectSlot + 0x0) = 0;
            *(undefined4*)(trackedObjectSlot + 0x4) = 0;
            *(undefined4*)(trackedObjectSlot + 0x8) = 0;
            *(undefined4*)(trackedObjectSlot + 0xc) = 0;
            *(undefined4*)(trackedObjectSlot + 0x10) = 0;
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

/*
 * --INFO--
 *
 * Function: pressureswitchfb_getExtraSize
 * EN v1.0 Address: 0x8017AD88
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x8017ADC4
 * EN v1.1 Size: 8b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int pressureswitchfb_getExtraSize(void)
{
    return PRESSURESWITCHFB_EXTRA_SIZE;
}

/*
 * --INFO--
 *
 * Function: pressureswitchfb_free
 * EN v1.0 Address: 0x8017AD90
 * EN v1.0 Size: 36b
 * EN v1.1 Address: 0x8017ADCC
 * EN v1.1 Size: 36b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void pressureswitchfb_free(int obj)
{
    ObjGroup_RemoveObject(obj,PRESSURESWITCHFB_REMOVE_GROUP_ID);
}

#include "main/dll/cfguardian_state.h"
#include "main/audio/sfx_ids.h"
#include "main/effect_interfaces.h"
#include "main/game_object.h"
#include "main/dll/cfguardian.h"
#include "main/game_object.h"
#include "main/objseq.h"

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
    s16 unk1A;
    s16 unk1C;
    u8 unk1E;
    u8 pad1F[0x20 - 0x1F];
    s16 unk20;
    s16 unk22;
    s16 unk24;
    u8 pad26[0x28 - 0x26];
} PressureswitchfbPlacement;

extern int ObjGroup_FindNearestObject();
extern undefined4 ObjGroup_AddObject();

extern f32 timeDelta;

/*
 * --INFO--
 *
 * Function: pressureswitchfb_update
 * EN v1.0 Address: 0x8017ADB4
 * EN v1.0 Size: 1540b
 * EN v1.1 Address: 0x8017B2F8
 * EN v1.1 Size: 1604b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
typedef struct
{
    u8 pad[4];
    u16 type;
    u16 arg;
    f32 w;
    f32 x;
    f32 y;
    f32 z;
} FxArgs;

typedef struct
{
    u8 active : 1;
    u8 playerOnly : 1;
    u8 released : 1;
    u8 latched : 1;
    u8 rest : 4;
} SwitchFlags;

extern void* Obj_GetPlayerObject(void);
extern int fn_80295C5C(void* player);
extern void* getTrickyObject(void);
extern f32 Vec_distance(f32 * a, f32 * b);
extern void Sfx_StopObjectChannel(int obj, int channel);
extern EffectInterface** gPartfxInterface;
extern int* objFindTexture(int* obj, int a, int b);
extern u32 GameBit_Get(int eventId);
extern int Sfx_PlayFromObject(int obj, int sfxId);
extern f32 lbl_803E3758;
extern f32 lbl_803E375C;
extern f32 lbl_803E3760;
extern f32 lbl_803E3764;
extern f32 lbl_803E3768;

void pressureswitchfb_update(int obj)
{
    extern int GameBit_Set(int eventId, int value); /* #57 */
    uint nearest;
    int off;
    uint other;
    int def;
    char* state;
    int i;
    int tmp;
    uint j;
    int isTarget;
    uint ju;
    int base;
    int* tex;
    f32 target;
    f32 cur;
    int slots2;
    u8 found;
    uint j2;
    uint ju2;
    uint o;
    int base2;
    f32 nearDist;
    FxArgs fx;

    def = *(int*)&((GameObject*)obj)->anim.placementData;
    state = ((GameObject*)obj)->extra;
    if ((((SwitchFlags*)(state + 0x84))->active) != 0)
    {
        if ((((SwitchFlags*)(state + 0x84))->released) == 0)
        {
            *(u8*)&((GameObject*)obj)->anim.resetHitboxMode |= 8;
        }
        else
        {
            *(u8*)&((GameObject*)obj)->anim.resetHitboxMode &= ~8;
        }
    }
    else
    {
        *(u8*)&((GameObject*)obj)->anim.resetHitboxMode |= 8;
    }
    if ((((PressureswitchfbPlacement*)def)->unk20 == -1) || (GameBit_Get(((PressureswitchfbPlacement*)def)->unk20) !=
        0))
    {
        u8 c = *state;
        *state = c - 1;
        if ((s8)(c - 1) < 0)
        {
            *state = 0;
        }
        nearDist = lbl_803E3758;
        nearest = (uint)ObjGroup_FindNearestObject(5, obj, &nearDist);
        if (nearest != 0)
        {
            *state = 5;
        }
        if (*(s8*)(*(int*)(obj + 0x58) + 0x10f) > 0)
        {
            for (i = 0, off = 0; i < *(s8*)(*(int*)(obj + 0x58) + 0x10f); i++)
            {
                other = *(uint*)(*(int*)(obj + 0x58) + off + 0x100);
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
                            if (other == (uint)Obj_GetPlayerObject())
                            {
                                goto do_insert;
                            }
                            goto skip_insert;
                        }
                    do_insert:
                        while ((*(uint*)(tmp + (j & 0xff) * 4 + 4) != 0) && ((j & 0xff) != 9))
                        {
                            j++;
                        }
                        ju = j & 0xff;
                        *(uint*)(tmp + ju * 4 + 4) = other;
                        base = tmp + ju * 8;
                        *(f32*)(base + 0x2c) = ((GameObject*)other)->anim.localPosX;
                        *(f32*)(base + 0x30) = ((GameObject*)other)->anim.localPosZ;
                    skip_insert: ;
                    }
                }
                off += 4;
            }
        }
        slots2 = *(int*)&((GameObject*)obj)->extra;
        found = 0;
        for (j2 = 0; (j2 & 0xff) < 10; j2++)
        {
            ju2 = j2 & 0xff;
            o = *(uint*)(slots2 + ju2 * 4 + 4);
            if (o != 0)
            {
                base2 = slots2 + ju2 * 8;
                if ((*(f32*)(base2 + 0x2c) == ((GameObject*)o)->anim.localPosX) &&
                    (*(f32*)(base2 + 0x30) == ((GameObject*)o)->anim.localPosZ))
                {
                    found = 1;
                }
                else
                {
                    *(int*)(slots2 + ju2 * 4 + 4) = 0;
                }
            }
        }
        if (found)
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
                    GameBit_Set(((PressureswitchfbPlacement*)def)->unk1A, 1);
                    if ((((SwitchFlags*)(state + 0x84))->active) != 0)
                    {
                        tex = (int*)objFindTexture((int*)obj, 0, 0);
                        if (tex != NULL)
                        {
                            *tex = 0x100;
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
                        GameBit_Set(((PressureswitchfbPlacement*)def)->unk1A, 1);
                        if ((((SwitchFlags*)(state + 0x84))->active) != 0)
                        {
                            tex = (int*)objFindTexture((int*)obj, 0, 0);
                            if (tex != NULL)
                            {
                                *tex = 0x100;
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
                        GameBit_Set(((PressureswitchfbPlacement*)def)->unk1A, 0);
                    }
                    else
                    {
                        i = 1;
                    }
                }
            }
            else
            {
                if (GameBit_Get(((PressureswitchfbPlacement*)def)->unk1A) == 0)
                {
                    tex = (int*)objFindTexture((int*)obj, 0, 0);
                    if (tex != NULL)
                    {
                        *tex = 0;
                    }
                    ((SwitchFlags*)(state + 0x84))->latched = 0;
                    ((SwitchFlags*)(state + 0x84))->released = 1;
                }
            }
        }
        if (((((GameObject*)obj)->objectFlags & 0x800) != 0) && ((((SwitchFlags*)(state + 0x84))->latched) == 0) &&
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
        if (((((PressureswitchfbPlacement*)def)->unk1E != 0) && ((tmp = (int)getTrickyObject()) != 0)) &&
            (GameBit_Get(((PressureswitchfbPlacement*)def)->unk1A) == 0))
        {
            *(u8*)&((GameObject*)obj)->anim.resetHitboxMode &= ~8;
            if ((*(u8*)&((GameObject*)obj)->anim.resetHitboxMode & 4) != 0)
            {
                (*(code*)(*(int*)(((PressureswitchfbState*)tmp)->unk68) + 0x28))(tmp, obj, 1, 3);
            }
        }
    }
}

/*
 * --INFO--
 *
 * Function: FUN_8017b3bc
 * EN v1.0 Address: 0x8017B3BC
 * EN v1.0 Size: 768b
 * EN v1.1 Address: 0x8017BB20
 * EN v1.1 Size: 796b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling on
#pragma peephole on

/*
 * --INFO--
 *
 * Function: FUN_8017b6bc
 * EN v1.0 Address: 0x8017B6BC
 * EN v1.0 Size: 32b
 * EN v1.1 Address: 0x8017BE3C
 * EN v1.1 Size: 36b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off

/*
 * --INFO--
 *
 * Function: FUN_8017b6dc
 * EN v1.0 Address: 0x8017B6DC
 * EN v1.0 Size: 204b
 * EN v1.1 Address: 0x8017BE60
 * EN v1.1 Size: 196b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling on
#pragma peephole on

/*
 * --INFO--
 *
 * Function: FUN_8017b7a8
 * EN v1.0 Address: 0x8017B7A8
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8017BF24
 * EN v1.1 Size: 464b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off

/*
 * --INFO--
 *
 * Function: FUN_8017b7ac
 * EN v1.0 Address: 0x8017B7AC
 * EN v1.0 Size: 172b
 * EN v1.1 Address: 0x8017C0F4
 * EN v1.1 Size: 192b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling on
#pragma peephole on

/* Trivial 4b 0-arg blr leaves. */
#pragma scheduling off
#pragma peephole off
void mmp_bridge_free(void);

extern f32 lbl_803E3778;
__declspec(section ".sdata") extern char lbl_803DBD90[];

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
    int* tex;
    f32 defaultOffset;
    PressureSwitchFbFlags* flags;

    objAnim = (ObjAnimComponent*)obj;
    sub = ((GameObject*)obj)->extra;
    flags = (PressureSwitchFbFlags*)(sub + 0x84);
    *(s16*)obj = (s16)(params[0x18] << 8);
    ((GameObject*)obj)->objectFlags = (u16)(((GameObject*)obj)->objectFlags | 0x6000);
    objAnim->bankIndex = (s8)params[0x19];
    if (objAnim->bankIndex >= objAnim->modelInstance->modelCount)
    {
        objAnim->bankIndex = 0;
    }
    defaultOffset = lbl_803E3778;
    ((CfGuardianState*)sub)->velocityY = defaultOffset;
    if (((GameObject*)obj)->anim.seqId == 0x77b)
    {
        flags->usePressedTexture = 1;
        flags->startPressed = 1;
        flags->canRelease = 1;
        ((CfGuardianState*)sub)->velocityY = defaultOffset;
    }
    ((CfGuardianState*)sub)->targetPosY = *(f32*)(params + 0xc);
    if (GameBit_Get(*(s16*)(params + 0x1a)) != 0)
    {
        s16 model;
        ((GameObject*)obj)->anim.localPosY = ((CfGuardianState*)sub)->targetPosY - (f32)(u32)
        params[0x1c];
        sub[0] = 0x1e;
        flags->canRelease = 0;
        model = ((GameObject*)obj)->anim.seqId;
        if (model != 0x19f)
        {
            if (model != 0x26c)
            {
                if (model != 0x274)
                {
                    if (model != 0x545)
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
                *tex = 0x100;
            }
        }
    }
    ObjGroup_AddObject(obj, 0x53);
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
    ((GameObject*)obj)->animEventCallback = (void*)pressureswitchfb_updateStateMode;
}

/* 8b "li r3, N; blr" returners. */
int Door_getExtraSize(void);

/* render-with-fn(lbl) (no visibility check). */

/* ObjGroup_RemoveObject(x, N) wrappers. */

/*
 * --INFO--
 *
 * Function: Door_SeqFn
 * EN v1.0 Address: 0x8017B5C8
 * EN v1.0 Size: 788b
 */

/*
 * --INFO--
 *
 * Function: Lock_DoorLock_SeqFn
 * EN v1.0 Address: 0x8017BCF8
 * EN v1.0 Size: 180b
 */

/*
 * --INFO--
 *
 * Function: doorlock_update
 * EN v1.0 Address: 0x8017BE28
 * EN v1.0 Size: 848b
 */

/* segment pragma-stack balance (re-split): */
#pragma scheduling reset
#pragma scheduling reset
#pragma scheduling reset
#pragma scheduling reset
#pragma scheduling reset
#pragma scheduling reset
#pragma peephole reset
#pragma peephole reset
#pragma peephole reset
#pragma peephole reset
#pragma peephole reset
#pragma peephole reset

#include "main/dll/alphaanim.h"
#include "main/game_object.h"
#include "main/objanim_internal.h"
#include "main/objseq.h"

extern uint GameBit_Get(int eventId);

/*
 * --INFO--
 *
 * Function: doorlock_init
 * EN v1.0 Address: 0x8017C178
 * EN v1.0 Size: 184b
 * EN v1.1 Address: 0x8017C250
 * EN v1.1 Size: 188b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */

/*
 * --INFO--
 *
 * Function: FUN_8017c5c4
 * EN v1.0 Address: 0x8017C5C4
 * EN v1.0 Size: 68b
 * EN v1.1 Address: 0x8017C7EC
 * EN v1.1 Size: 64b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */

/*
 * --INFO--
 *
 * Function: FUN_8017c608
 * EN v1.0 Address: 0x8017C608
 * EN v1.0 Size: 456b
 * EN v1.1 Address: 0x8017C82C
 * EN v1.1 Size: 308b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */

/*
 * --INFO--
 *
 * Function: seqObject_free
 * EN v1.0 Address: 0x8017C7D0
 * EN v1.0 Size: 36b
 * EN v1.1 Address: 0x8017C960
 * EN v1.1 Size: 36b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */

/*
 * --INFO--
 *
 * Function: seqObject_render
 * EN v1.0 Address: 0x8017C7F4
 * EN v1.0 Size: 40b
 * EN v1.1 Address: 0x8017C984
 * EN v1.1 Size: 48b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */

/*
 * --INFO--
 *
 * Function: seqObject_update
 * EN v1.0 Address: 0x8017C81C
 * EN v1.0 Size: 548b
 * EN v1.1 Address: 0x8017C9B4
 * EN v1.1 Size: 592b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */

/*
 * --INFO--
 *
 * Function: seqObject_init
 * EN v1.0 Address: 0x8017CA40
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8017CC04
 * EN v1.1 Size: 248b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */

/*
 * --INFO--
 *
 * Function: seqObj2_free
 * EN v1.0 Address: 0x8017CAF4
 * EN v1.0 Size: 36b
 * EN v1.1 Address: 0x8017CDE4
 * EN v1.1 Size: 44b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */

/*
 * --INFO--
 *
 * Function: seqObj2_update
 * EN v1.0 Address: 0x8017CB18
 * EN v1.0 Size: 460b
 * EN v1.1 Address: 0x8017CE10
 * EN v1.1 Size: 596b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */

/*
 * --INFO--
 *
 * Function: seqObj2_init
 * EN v1.0 Address: 0x8017CCE4
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8017D064
 * EN v1.1 Size: 200b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */

/* Trivial 4b 0-arg blr leaves. */

/* 8b "li r3, N; blr" returners. */

/* render-with-objRenderFn_8003b8f4 pattern. */

/* ObjGroup_RemoveObject(x, N) wrappers. */

/* Drift-recovery: add new fns with v1.0 names. */

/* immultiseq_SeqFn: seqobj2 advance-state predicate. If obj has a trigger id
 * (-1 sentinel skips), peek at the next state slot in def[0x20+n*2], read
 * its GameBit, compare against the def[0x30] mask bit for that slot, and
 * if the polarity flips (GameBit != mask bit) end the current sequence.
 * Always latches state[1] bit 0 before returning 0. */
