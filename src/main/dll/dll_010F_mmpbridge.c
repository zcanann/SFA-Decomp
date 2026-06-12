/* === merged from main/dll/texScroll.c [8017AC2C-8017ADB4) (TU re-split, docs/boundary_audit.md) === */
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
undefined4 pressureswitchfb_updateStateMode(int obj, undefined4 param_2, int stateParam);

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
int pressureswitchfb_getExtraSize(void);

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
void pressureswitchfb_free(int obj);

#include "main/dll/cfguardian_state.h"
#include "main/audio/sfx_ids.h"
#include "main/effect_interfaces.h"
#include "main/game_object.h"
#include "main/dll/cfguardian.h"
#include "main/game_object.h"
#include "main/objseq.h"

typedef struct MmpBridgePlacement
{
    u8 pad0[0x4 - 0x0];
    u8 unk4;
    u8 unk5;
    u8 unk6;
    u8 pad7[0x18 - 0x7];
    s8 unk18;
    u8 pad19[0x1E - 0x19];
    s16 unk1E;
} MmpBridgePlacement;


typedef struct PressureswitchfbState
{
    u8 pad0[0x68 - 0x0];
    s32 unk68;
    u8 pad6C[0x70 - 0x6C];
} PressureswitchfbState;


typedef struct DoorObjectDef
{
    u8 pad0[0x18 - 0x0];
    s16 unk18;
    s16 unk1A;
    u8 unk1C;
    u8 unk1D;
    u8 pad1E[0x20 - 0x1E];
    u8 unk20;
    u8 unk21;
    s16 unk22;
    u8 pad24[0x28 - 0x24];
} DoorObjectDef;


typedef struct LockDoorLockPlacement
{
    u8 pad0[0x18 - 0x0];
    s16 unk18;
    s16 unk1A;
    s16 unk1C;
    u8 pad1E[0x20 - 0x1E];
    u8 unk20;
    u8 unk21;
    s16 unk22;
    s16 unk24;
    u8 pad26[0x28 - 0x26];
} LockDoorLockPlacement;


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


typedef struct DoorPlacement
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
} DoorPlacement;


typedef struct DoorlockPlacement
{
    u8 pad0[0x18 - 0x0];
    s16 unk18;
    s16 unk1A;
    s16 unk1C;
    s16 unk1E;
    s16 unk20;
    s16 unk22;
    s16 unk24;
    s16 unk26;
} DoorlockPlacement;




extern undefined4 ObjHits_DisableObject();
extern undefined4 ObjHits_EnableObject();
extern int ObjGroup_FindNearestObject();
extern undefined4 ObjGroup_AddObject();

extern ObjectTriggerInterface** gObjectTriggerInterface;
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

void pressureswitchfb_update(int obj);


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
void mmp_bridge_free(void)
{
}

void mmp_bridge_render(void)
{
}

void mmp_bridge_hitDetect(void)
{
}

void mmp_bridge_release(void)
{
}

void mmp_bridge_initialise(void)
{
}

extern f32 lbl_803E3778;
__declspec(section ".sdata") extern char lbl_803DBD90[];
extern void fn_80137948(char* fmt, ...);

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

void pressureswitchfb_init(u8* obj, u8* params);

/* 8b "li r3, N; blr" returners. */
int Door_getExtraSize(void);
int mmp_bridge_getExtraSize(void) { return 0x0; }
int mmp_bridge_getObjectTypeId(void) { return 0x0; }
int doorlock_getExtraSize(void);

/* render-with-fn(lbl) (no visibility check). */
extern f32 lbl_803E3780;
extern void objRenderFn_8003b8f4(f32);
void Door_render(void);

/* ObjGroup_RemoveObject(x, N) wrappers. */
void doorlock_free(int x);

void mmp_bridge_init(int* obj)
{
    int* state = *(int**)&((GameObject*)obj)->anim.placementData;
    int* tex = objFindTexture(obj, 0, 0);
    if (tex != NULL)
    {
        *(s16*)((char*)tex + 8) = 0x800;
    }
    *(s16*)obj = (s16)(((MmpBridgePlacement*)state)->unk18 << 8);
    ((GameObject*)obj)->objectFlags |= 0x6000;
    ObjHits_DisableObject((int)obj);
    if (GameBit_Get(((MmpBridgePlacement*)state)->unk1E) != 0)
    {
        ObjHits_EnableObject((int)obj);
    }
}

extern f32 lbl_803E3798;
extern void objRenderFn_80041018(int* obj);

void doorlock_render(int* obj, int p2, int p3, int p4, int p5, s8 visible);

int Door_SeqFn(int obj, int unused, ObjAnimUpdateState* animUpdate);
extern f32 lbl_803E3784;
extern f32 lbl_803E3788;
extern f32 lbl_803E3790;

void Door_init(int* obj, u8* def);

void Door_update(int obj);

void mmp_bridge_update(int* obj)
{
    int* tex;
    int frame;

    if (GameBit_Get(*(s16*)((char*)obj[0x4c / 4] + 0x1e)) != 0)
    {
        tex = objFindTexture(obj, 0, 0);
        if (tex != NULL)
        {
            frame = *(s16*)((char*)tex + 8) + ((int)timeDelta << 3);
            *(s16*)((char*)tex + 8) = (s16)frame;
            frame = *(s16*)((char*)tex + 8) + ((int)timeDelta << 3);
            if (frame >= 0x131f)
            {
                *(s16*)((char*)tex + 8) = 0x131f;
            }
            fn_80137948(lbl_803DBD90, (int)*(s16*)((char*)tex + 8));
        }
        ObjHits_EnableObject((int)obj);
    }
}

extern int Sfx_IsPlayingFromObject(int obj, int sfxId);
extern int Sfx_StopFromObject(int obj, int sfxId);
extern int ObjTrigger_IsSetById(int obj, int id);
extern int ObjTrigger_IsSet(int obj);
extern void buttonDisable(int index, int mask);

/*
 * --INFO--
 *
 * Function: Door_SeqFn
 * EN v1.0 Address: 0x8017B5C8
 * EN v1.0 Size: 788b
 */
int Door_SeqFn(int obj, int unused, ObjAnimUpdateState* animUpdate);

/*
 * --INFO--
 *
 * Function: Lock_DoorLock_SeqFn
 * EN v1.0 Address: 0x8017BCF8
 * EN v1.0 Size: 180b
 */
int Lock_DoorLock_SeqFn(int obj, int unused, ObjAnimUpdateState* animUpdate);

/*
 * --INFO--
 *
 * Function: doorlock_update
 * EN v1.0 Address: 0x8017BE28
 * EN v1.0 Size: 848b
 */
void doorlock_update(int obj);

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

/* === moved from main/dll/alphaanim.c [8017C178-8017C294) (TU re-split, docs/boundary_audit.md) === */
#include "main/dll/alphaanim.h"
#include "main/game_object.h"
#include "main/objanim_internal.h"
#include "main/objseq.h"


extern uint GameBit_Get(int eventId);


typedef struct DoorLockState
{
    u8 unlocked;
} DoorLockState;








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
void doorlock_init(short* obj, DoorLockPlacement* config);


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
undefined4 FUN_8017c608(undefined8 param_1, double param_2, double param_3, undefined8 param_4, undefined8 param_5, undefined8 param_6, undefined8 param_7, undefined8 param_8, int param_9, undefined4 param_10 , ObjAnimUpdateState* animUpdate, undefined4 param_12, int param_13, undefined4 param_14, undefined4 param_15, undefined4 param_16);

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
