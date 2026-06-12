/* === moved from main/dll/WC/WClaser.c [801F0AE4-801F0B50) (TU re-split, docs/boundary_audit.md) === */
#include "main/dll/WC/WClaser.h"
#include "main/dll/WC/WCpressureSwitch.h"
#include "main/effect_interfaces.h"
#include "main/game_object.h"
#include "main/mapEventTypes.h"
#include "main/objanim.h"
#include "main/obj_placement.h"
#include "main/objlib.h"
#include "main/objseq.h"
#include "main/screen_transition.h"

extern int Obj_GetPlayerObject(void);
extern void objSetSlot(int* obj, int slot);
extern void objHitDetectFn_80062e84(int player, int hitObj, int mode);
extern void objRenderFn_8003b8f4(f32 scale);
extern void fn_80065574(int a, int* obj, int b);
extern void fn_80296BBC(int player);
extern void buttonDisable(int controller, int mask);
extern void textureFree(void* resource);

extern MapEventInterface** gMapEventInterface;
extern ObjectTriggerInterface** gObjectTriggerInterface;
extern ScreenTransitionInterface** gScreenTransitionInterface;
extern ModgfxInterface** gModgfxInterface;

extern f32 timeDelta;
extern u8 lbl_803DDC78;
extern f32 lbl_803E5CEC;
extern f32 lbl_803E5CF0;
extern f32 lbl_803E5CF4;
extern f32 lbl_803E5CF8;
extern f32 lbl_803E5D00;
extern f32 lbl_803E5D04;
extern f32 lbl_803E5D08;

#define OBJ_U8(obj, offset) (*(u8 *)((u8 *)(obj) + (offset)))
#define OBJ_S8(obj, offset) (*(s8 *)((u8 *)(obj) + (offset)))
#define OBJ_S16(obj, offset) (*(s16 *)((u8 *)(obj) + (offset)))
#define OBJ_S32(obj, offset) (*(s32 *)((u8 *)(obj) + (offset)))
#define OBJ_F32(obj, offset) (*(f32 *)((u8 *)(obj) + (offset)))
#define OBJ_PTR(obj, offset) (*(void **)((u8 *)(obj) + (offset)))

#define MAP_EVENT_TEST(mapId, eventId) \
    (*gMapEventInterface)->getAnimEvent((mapId), (eventId))
#define MAP_EVENT_SET(mapId, eventId, value) \
    (*gMapEventInterface)->setAnimEvent((mapId), (eventId), (value))
#define OBJECT_TRIGGER_REFRESH(eventId, obj, arg) \
    (*gObjectTriggerInterface)->runSequence((eventId), (obj), (arg))
#define SCREEN_TRANSITION_START(kind, value) \
    (*gScreenTransitionInterface)->step((kind), (value))

typedef struct Dll1FBSetup
{
    ObjPlacement base;
    s8 yawByte;
    s8 baseMove;
    s16 triggerMode;
    s16 objectParam;
} Dll1FBSetup;

typedef struct WMGalleonSetup
{
    ObjPlacement base;
    s8 yawByte;
} WMGalleonSetup;

typedef struct WMSeqObjectSetup
{
    ObjPlacement base;
    s8 yawByte;
    s8 setupType;
} WMSeqObjectSetup;

typedef struct WMGalleonState
{
    f32 savedX;
    f32 savedY;
    f32 savedZ;
    u8 mapEventsLatched;
    u8 pad0D;
    s16 savedYaw;
} WMGalleonState;

typedef struct Dll1FBState
{
    u8 pad00[4];
    s16 baseMove;
    s16 triggerMode;
    u8 pad08;
    u8 hideModel;
    u8 pad0A[2];
} Dll1FBState;

STATIC_ASSERT(sizeof(Dll1FBState) == 0xc);
STATIC_ASSERT(offsetof(Dll1FBState, baseMove) == 0x04);
STATIC_ASSERT(offsetof(Dll1FBState, triggerMode) == 0x06);
STATIC_ASSERT(offsetof(Dll1FBState, hideModel) == 0x09);
STATIC_ASSERT(sizeof(WMGalleonState) == 0x10);
STATIC_ASSERT(offsetof(WMGalleonState, savedX) == 0x00);
STATIC_ASSERT(offsetof(WMGalleonState, savedY) == 0x04);
STATIC_ASSERT(offsetof(WMGalleonState, savedZ) == 0x08);
STATIC_ASSERT(offsetof(WMGalleonState, mapEventsLatched) == 0x0C);
STATIC_ASSERT(offsetof(WMGalleonState, savedYaw) == 0x0E);
STATIC_ASSERT(offsetof(Dll1FBSetup, yawByte) == 0x18);
STATIC_ASSERT(offsetof(Dll1FBSetup, baseMove) == 0x19);
STATIC_ASSERT(offsetof(Dll1FBSetup, triggerMode) == 0x1a);
STATIC_ASSERT(offsetof(Dll1FBSetup, objectParam) == 0x1c);
STATIC_ASSERT(offsetof(WMGalleonSetup, yawByte) == 0x18);
STATIC_ASSERT(offsetof(WMSeqObjectSetup, yawByte) == 0x18);
STATIC_ASSERT(offsetof(WMSeqObjectSetup, setupType) == 0x19);

void WM_Galleon_update(int* obj);

void WM_Galleon_init(int* obj, WMGalleonSetup* setup);

void WM_Galleon_release(void);

void WM_Galleon_initialise(void);

int WM_seqobject_SeqFn(int obj, int unused, ObjAnimUpdateState* animUpdate);

int WM_seqobject_getExtraSize(void);
int WM_seqobject_getObjectTypeId(void);

void WM_seqobject_free(void);

void WM_seqobject_render(int p1, int p2, int p3, int p4, int p5, s8 visible);

void WM_seqobject_hitDetect(void);

void WM_seqobject_update(int* obj);

void WM_seqobject_init(int* obj, s8* def);

void WM_seqobject_release(void);

void WM_seqobject_initialise(void);

int dll_1FB_SeqFn(int* obj, int unused, ObjAnimUpdateState* animUpdate);

int dll_1FB_getExtraSize_ret_12(void);
int dll_1FB_getObjectTypeId(void);

void dll_1FB_free_nop(void);

void dll_1FB_render(int* obj, int p2, int p3, int p4, int p5, s8 visible);

void dll_1FB_hitDetect_nop(void);

void dll_1FB_update(int* obj);

void dll_1FB_init(int* obj, u8* def);

void dll_1FB_release_nop(void);

void dll_1FB_initialise_nop(void);

int LaserBeam_getExtraSize(void) { return 0x50; }
int LaserBeam_getObjectTypeId(void) { return 0; }

void LaserBeam_init(int* obj)
{
    void** state;

    state = (void**)OBJ_PTR(obj, 0xb8);
    (*gModgfxInterface)->detachSource(obj);
    if (state[0] != 0)
    {
        textureFree(state[0]);
        state[0] = 0;
    }
}

void LaserBeam_render(void)
{
}

void LaserBeam_hitDetect(void)
{
}

#include "main/audio/sfx_ids.h"
#include "main/effect_interfaces.h"
#include "main/expgfx.h"
#include "main/game_ui_interface.h"
#include "main/game_object.h"
#include "main/mapEvent.h"
#include "main/dll/ARW/ARWarwingattachment.h"
#include "main/objHitReact.h"
#include "main/objanim_internal.h"
#include "main/objseq.h"
#include "main/resource.h"
#include "global.h"

typedef struct LaserBeamPlacement
{
    u8 pad0[0x1A - 0x0];
    s16 unk1A;
    u8 pad1C[0x1E - 0x1C];
    s16 unk1E;
    u8 pad20[0x4C - 0x20];
    u8 unk4C;
    u8 pad4D[0x2F8 - 0x4D];
    u8 unk2F8;
    u8 unk2F9;
    s8 unk2FA;
    u8 pad2FB[0x300 - 0x2FB];
} LaserBeamPlacement;


typedef struct WMColrisePlacement
{
    u8 pad0[0xC - 0x0];
    f32 unkC;
} WMColrisePlacement;


typedef struct LightsourceState
{
    u8 pad0[0x4C - 0x0];
    u8 unk4C;
    u8 pad4D[0x2F8 - 0x4D];
    u8 unk2F8;
    u8 pad2F9[0x300 - 0x2F9];
} LightsourceState;


typedef struct WmlasertargetPlacement
{
    u8 pad0[0xC - 0x0];
    f32 unkC;
    u8 pad10[0x1A - 0x10];
    s16 cooldown;
    u8 pad1C[0x1E - 0x1C];
    s16 unk1E;
    s16 unk20;
    u8 pad22[0x28 - 0x22];
} WmlasertargetPlacement;


typedef struct PressureswitchPlacement
{
    u8 pad0[0xC - 0x0];
    f32 unkC;
    u8 pad10[0x1A - 0x10];
    s16 unk1A;
    s16 unk1C;
    s16 unk1E;
    u8 pad20[0x4C - 0x20];
    u8 unk4C;
    u8 pad4D[0x2F8 - 0x4D];
    u8 unk2F8;
    u8 unk2F9;
    s8 unk2FA;
    u8 pad2FB[0x300 - 0x2FB];
} PressureswitchPlacement;


/* Per-object extra state for the WM laser beam emitter. */
typedef struct LaserBeamState
{
    int texture;
    f32 unk04; /* 0x04: cur/prev pair A (reset each update) */
    f32 unk08;

    f32 beamX; /* 0x0c: beam base position */
    f32 beamX2; /* 0x10 */
    f32 beamZ; /* 0x14 */
    f32 beamZ2; /* 0x18 */
    f32 sweepPhase; /* 0x1c */
    u8 pad20[4];
    u8 unk24;
    u8 unk25;
    u8 unk26;
    s8 unk27;
    s16 unk28;
    s16 sweepYaw; /* 0x2a */
    s16 fireTimer; /* 0x2c */
    s16 unk2E;
    s16 firePeriod; /* 0x30 */
    s16 emitterSlot; /* 0x32: modgfx handle head */
    u8 pad34[0xc];
    f32 targetX; /* 0x40 */
    u8 pad44[4];
    f32 targetZ; /* 0x48 */
    u8 unk4C;
    u8 active; /* 0x4d */
    u8 beamKind; /* 0x4e: 30/1/other texture pick */
} LaserBeamState;

STATIC_ASSERT(offsetof(LaserBeamState, beamKind) == 0x4e);

/* pressureswitch_getExtraSize == 0x8. */
typedef struct PressureSwitchState
{
    s8 holdTimer; /* frames the switch stays pressed */
    s8 chimeLatch;
    s16 retriggerTimer;
    s16 mapGameBit; /* 0xf45/0xf46 per-map bit, -1 none */
    u8 flags; /* PressureSwitchFlags / PswFlags overlay */
    u8 pad7;
} PressureSwitchState;

/* wmlasertarget_getExtraSize == 0x4. */
typedef struct WmLaserTargetState
{
    s16 cooldown;
    u8 toggleQueued;
    u8 pad3;
} WmLaserTargetState;

/* WM_colrise_getExtraSize == 0x4. */
typedef struct WMColriseState
{
    s16 gameBit;
    u8 raiseTimer;
    u8 pad3;
} WMColriseState;

/* wmtorch_getExtraSize == 0x10. */
typedef struct WmTorchState
{
    void* linkedObj;
    f32 unk04;
    u8 pad08[2];
    s16 unk0A;
    u8 torchType; /* params[0x19]: 0 / 0x7f / other */
    u8 pad0D[3];
} WmTorchState;

/* lightsource_getExtraSize == 0x1c. */
typedef struct LightSourceState
{
    void* light;
    f32 fxTimer;
    u8 pad08[4];
    f32 sparkTimer;
    int gameBit; /* 0x10: -1 none */
    u8 mode; /* 0x14: 1 = hit-toggleable */
    u8 fxType;
    u8 fxArg;
    u8 lit; /* 0x17 */
    u8 litPrev;
    u8 sparks; /* 0x19 */
    u8 loopFlags; /* 0x1a: LightSourceFlagByte */
    u8 pad1B;
} LightSourceState;

STATIC_ASSERT(sizeof(LightSourceState) == 0x1c);

/* dll_1FF_getExtraSize == 0x8 (grabbable hook). */
typedef struct Dll1FFState
{
    s16 msgLo;
    s16 msgHi;
    u8 pad4;
    s8 grabPhase; /* 0 free, 1 held, 2 releasing */
    u8 sendFlag; /* 0x6 */
    u8 pad7;
} Dll1FFState;

/* dll_200_getExtraSize == 0x28 (kid attachment actor). */
typedef struct Dll200State
{
    f32 homeX;
    f32 homeY;
    f32 homeZ;
    f32 animSpeed; /* 0x0c */
    f32 hitReactVec; /* 0x10: head of the f32 pair ObjHitReact_Update fills */
    f32 unk14;
    s16 unk18;
    u8 pad1A[2];
    u32 unk1C;
    s16 modeTimer; /* 0x20 */
    u8 mode; /* 0x22: 1-5 wander, 12 turn, 13 play */
    u8 prevMode; /* 0x23 */
    u8 latch24; /* 0x24: GameBit 0xd0 latch */
    u8 mode25; /* 0x25: trigger pick */
    u8 defNoLow; /* 0x26 */
    s8 counter27; /* 0x27: hug/talk counter */
} Dll200State;

STATIC_ASSERT(sizeof(Dll200State) == 0x28);

extern undefined4 FUN_8000680c();
extern undefined4 FUN_80006824();
extern undefined8 FUN_80006ba8();
extern uint FUN_80006c00();
extern undefined4 FUN_8001771c();
extern u32 randomGetRange(int min, int max);
extern uint FUN_80017a98();
extern int ObjHits_GetPriorityHit();
extern undefined4 ObjMsg_SendToObject();
extern int FUN_800632f4();

extern ObjectTriggerInterface** gObjectTriggerInterface;
extern ModgfxInterface** gModgfxInterface;
extern MapEventInterface** gMapEventInterface;
extern f32 lbl_803DC074;
extern f32 lbl_803E6A1C;
extern f32 lbl_803E6A20;
extern f32 lbl_803E6A24;
extern f32 lbl_803E6A80;

/*
 * --INFO--
 *
 * Function: LaserBeam_update
 * EN v1.0 Address: 0x801F0B50
 * EN v1.0 Size: 360b
 * EN v1.1 Address: 0x801F0DA4
 * EN v1.1 Size: 488b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void LaserBeam_update(int obj2)
{
    extern undefined4 GameBit_Set(int eventId, int value); /* #57 */
    extern uint GameBit_Get(int eventId); /* #57 */
    extern void*Obj_GetPlayerObject(void);
    extern uint GameBit_Get(int id);
    extern void Sfx_PlayFromObject(int obj, int sfx);
    extern void Sfx_PlayAtPositionFromObject(int obj, f32 x, f32 y, f32 z, int sfx);
    extern int objGetAnimState80A(void* obj);
    extern f32 mathCosf(f32 x);
    extern f32 mathSinf(f32 x);
    extern int* lbl_803DDC80;
    extern EffectInterface** gPartfxInterface;
    extern u8 framesThisStep;
    extern f32 timeDelta;
    extern f32 lbl_803E5D10;
    extern f32 lbl_803E5D14;
    extern f32 lbl_803E5D18;
    extern f32 lbl_803E5D1C;
    extern f32 lbl_803E5D20;
    extern f32 lbl_803E5D24;
    extern f32 lbl_803E5D28;
    extern f32 lbl_803E5D2C;
    extern f32 lbl_803E5D30;
    extern f32 lbl_803E5D34;
    extern f32 lbl_803E5D38;
    extern f32 lbl_803E5D3C;
    extern f32 lbl_803E5D40;
    extern f32 lbl_803E5D44;
    extern f32 lbl_803E5D48;
    char* t;
    LaserBeamState* b;
    char* player;
    u8 c;
    int i;
    u16 sfx;
    f32 dz;
    f32 dz2;
    f32 sinv;
    f32 cosv;
    f32 range;
    f32 dot;
    f32 dy;
    f32 dx;
    f32 dzp;
    f32 a;
    f32 lat;
    f32 spread;
    f32 fz;

    t = *(char**)&((GameObject*)obj2)->anim.placementData;
    b = ((GameObject*)obj2)->extra;
    b->fireTimer -= framesThisStep;
    if (GameBit_Get(((LaserBeamPlacement*)t)->unk1E) == 0)
    {
        if (b->fireTimer < 0)
        {
            if (b->unk25 == 0)
            {
                c = b->beamKind;
                if (c == 3 || c == 30)
                {
                    b->fireTimer = b->firePeriod;
                }
                else
                {
                    if (c == 0 && b->emitterSlot != -1)
                    {
                        (*gModgfxInterface)->releaseHandle(&b->emitterSlot);
                    }
                    b->fireTimer = b->firePeriod;
                }
                b->sweepPhase = lbl_803E5D10;
            }
            else
            {
                b->fireTimer = 150;
            }
            b->active = 0;
        }
        else if (b->fireTimer < b->unk2E)
        {
            if (b->active == 0)
            {
                b->active = 1;
                c = b->beamKind;
                if (c == 1)
                {
                    if (lbl_803DDC80 != NULL)
                    {
                        (*(s16 (**)(int, int, int, int, int, int))(*lbl_803DDC80 + 4))(
                            obj2, 2, 0, 0x10004, -1, 0);
                    }
                }
                else if (c != 30 && c != 0)
                {
                    (*(s16 (**)(int, int, int, int, int, int))(*lbl_803DDC80 + 4))(
                        obj2, 0, 0, 0x10004, -1, 0);
                }
            }
            if (b->fireTimer < 0x28)
            {
                if (b->sweepPhase >= lbl_803E5D10 && b->unk25 == 0)
                {
                    b->sweepPhase = -(lbl_803E5D14 * timeDelta - b->sweepPhase);
                }
            }
            else if (b->fireTimer < 0x8c)
            {
                if (b->active == 1)
                {
                    b->active = 2;
                    c = b->beamKind;
                    if (c == 1)
                    {
                        if (lbl_803DDC80 != NULL)
                        {
                            (*(s16 (**)(int, int, int, int, int, int))(*lbl_803DDC80 + 4))(
                                obj2, 3, 0, 0x10004, -1, 0);
                        }
                    }
                    else if (c == 30)
                    {
                        if (lbl_803DDC80 != NULL)
                        {
                            b->emitterSlot =
                                (*(s16 (**)(int, int, int, int, int, int))(*lbl_803DDC80 + 4))(
                                    obj2, 30, 0, 0x10004, -1, 0);
                        }
                    }
                    else if (c != 0)
                    {
                        if (lbl_803DDC80 != NULL)
                        {
                            (*(s16 (**)(int, int, int, int, int, int))(*lbl_803DDC80 + 4))(
                                obj2, 1, 0, 0x10004, -1, 0);
                        }
                    }
                    else
                    {
                        if (lbl_803DDC80 != NULL && b->emitterSlot == -1)
                        {
                            if (b->emitterSlot != -1)
                            {
                                (*gModgfxInterface)->releaseHandle(&b->emitterSlot);
                            }
                            if (lbl_803DDC80 != NULL)
                            {
                                b->emitterSlot =
                                    (*(s16 (**)(int, int, int, int, int, int))(*lbl_803DDC80 + 4))(
                                        obj2, 0, 0, 0x10004, -1, 0);
                            }
                        }
                    }
                }
            }
            else if (b->sweepPhase <= lbl_803E5D18)
            {
                b->sweepPhase = lbl_803E5D1C * timeDelta + b->sweepPhase;
            }
        }
    }
    else if (b->beamKind == 0 && b->emitterSlot != -1)
    {
        (*gModgfxInterface)->releaseHandle(&b->emitterSlot);
    }
    dz = (f32)(int)((LaserBeamPlacement*)t)->unk1A;
    dz2 = dz * dz;
    sinv = mathCosf((lbl_803E5D20 * (f32)(int)*(s16*)obj2) / lbl_803E5D24);
    cosv = mathSinf((lbl_803E5D20 * (f32)(int)*(s16*)obj2) / lbl_803E5D24);
    dot = -(((GameObject*)obj2)->anim.localPosX * sinv + ((GameObject*)obj2)->anim.localPosZ * cosv);
    player = Obj_GetPlayerObject();
    b->unk27 = (s8)(b->unk27 - framesThisStep);
    if (b->unk27 <= 0)
    {
        b->unk27 = 0;
    }
    else if (b->beamKind == 0 && b->emitterSlot != -1)
    {
        (*gModgfxInterface)->releaseHandle(&b->emitterSlot);
    }
    if ((dot + (sinv * ((GameObject*)player)->anim.localPosX + cosv * ((GameObject*)player)->anim.localPosZ) >
            lbl_803E5D10 &&
            b->beamKind != 2) ||
        b->beamKind == 30)
    {
        b->sweepYaw -= framesThisStep;
        if (b->sweepYaw < 0)
        {
            b->sweepYaw = 0;
            b->unk25 = 0;
        }
    }
    else
    {
        b->sweepYaw += framesThisStep;
        if (b->sweepYaw > 60)
        {
            b->sweepYaw = 60;
            b->unk25 = 1;
        }
    }
    if (b->unk25 == 0)
    {
        b->unk24 = (u8)(b->active & 3);
    }
    else
    {
        b->unk24 = 2;
    }
    if (GameBit_Get(((LaserBeamPlacement*)t)->unk1E) != 0)
    {
        b->unk24 = 0;
    }
    if (b->unk27 == 0)
    {
        b->unk28 = 0;
    }
    if (player != NULL && b->unk27 == 0 && b->unk24 == 2)
    {
        range = lbl_803E5D28 + (f32)(int)*(s8*)&b->unk26;
        dy = ((GameObject*)player)->anim.localPosY - ((GameObject*)obj2)->anim.localPosY;
        if (dy < range && dy > -(lbl_803E5D2C + range))
        {
            dx = ((GameObject*)player)->anim.localPosX - ((GameObject*)obj2)->anim.localPosX;
            dzp = ((GameObject*)player)->anim.localPosZ - ((GameObject*)obj2)->anim.localPosZ;
            if (dx * dx + dzp * dzp < dz2)
            {
                lat = dot + (sinv * ((GameObject*)player)->anim.localPosX + cosv * ((GameObject*)player)->anim.
                    localPosZ);
                a = lat;
                if (lat < lbl_803E5D10)
                {
                    a = -lat;
                }
                if (a > lbl_803E5D30)
                {
                    a = lbl_803E5D30;
                }
                b->unk28 = (s16)(int)((lbl_803E5D30 - a) * lbl_803E5D34);
                if (!(lat < lbl_803E5D38 && lat > lbl_803E5D3C) && b->unk4C == 1)
                {
                    (*gModgfxInterface)->detachSource((void*)obj2);
                    b->unk4C = 0;
                }
                if (lat < range && lat > -range)
                {
                    if (objGetAnimState80A(player) == 0x1d7 && b->beamKind != 1)
                    {
                        GameBit_Set(0x468, 1);
                    }
                    else
                    {
                        if (dot + (sinv * ((GameObject*)player)->anim.previousLocalPosX +
                            cosv * ((GameObject*)player)->anim.previousLocalPosZ) < lbl_803E5D10)
                        {
                            spread = lbl_803E5D40;
                        }
                        else
                        {
                            spread = lbl_803E5D44;
                        }
                        Sfx_PlayAtPositionFromObject(obj2, ((GameObject*)player)->anim.localPosX,
                                                     ((GameObject*)obj2)->anim.localPosY,
                                                     ((GameObject*)player)->anim.localPosZ, 0x1c9);
                        if (*(s16*)(*(char**)&((GameObject*)player)->extra + 0x81a) == 0)
                        {
                            sfx = 31;
                        }
                        else
                        {
                            sfx = 35;
                        }
                        Sfx_PlayFromObject((int)player, sfx);
                        for (i = 0; i < 4; i++)
                        {
                            (*gPartfxInterface)->spawnObject(Obj_GetPlayerObject(), 0x198,
                                                             NULL, 4, -1, NULL);
                        }
                        b->targetX = sinv * spread + ((GameObject*)player)->anim.localPosX;
                        b->targetZ = cosv * spread + ((GameObject*)player)->anim.localPosZ;
                        c = b->beamKind;
                        if (c == 0 || c == 1)
                        {
                            ObjMsg_SendToObject(player, 0x60003, (char*)b + 0x34, 0);
                        }
                        else if ((u8)(c - 2) <= 1 || c == 30)
                        {
                            ObjMsg_SendToObject(player, 0x60004, (char*)b + 0x34, 0);
                        }
                        *(u8*)&b->unk27 = 2;
                    }
                }
            }
        }
    }
    if (b->unk24 == 0)
    {
        if (b->beamKind == 30 && b->emitterSlot != -1)
        {
            (*gModgfxInterface)->releaseHandle(&b->emitterSlot);
        }
        if (b->unk4C == 1)
        {
            (*gModgfxInterface)->detachSource((void*)obj2);
            b->unk4C = 0;
        }
    }
    fz = lbl_803E5D10;
    b->unk04 = fz;
    b->beamX = fz;
    b->beamZ = fz;
    b->unk08 = b->unk04;
    b->beamX2 = b->beamX;
    b->beamZ2 = b->beamZ + dz;
    b->unk26 = 8;
    ((GameObject*)obj2)->anim.currentMoveProgress = lbl_803E5D48 * timeDelta + ((GameObject*)obj2)->anim.
        currentMoveProgress;
    if (((GameObject*)obj2)->anim.currentMoveProgress > lbl_803E5D18)
    {
        ((GameObject*)obj2)->anim.currentMoveProgress = ((GameObject*)obj2)->anim.currentMoveProgress -
            lbl_803E5D18;
    }
}


/*
 * --INFO--
 *
 * Function: FUN_801f1634
 * EN v1.0 Address: 0x801F1634
 * EN v1.0 Size: 768b
 * EN v1.1 Address: 0x801F22BC
 * EN v1.1 Size: 684b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801f1634(undefined8 param_1, undefined8 param_2, undefined8 param_3, undefined8 param_4,
                  undefined8 param_5, undefined8 param_6, undefined8 param_7, undefined8 param_8,
                  uint param_9)
{
    extern undefined4 ObjHits_EnableObject(); /* #57 */
    extern undefined8 ObjHits_DisableObject(); /* #57 */
    char cVar1;
    float fVar2;
    float fVar3;
    float fVar4;
    int iVar5;
    u8 uVar8;
    float* pfVar6;
    uint uVar7;
    int iVar9;
    float fVar10;
    int iVar11;
    undefined4 in_r7;
    undefined4 in_r8;
    undefined4 in_r9;
    undefined4 in_r10;
    undefined2* puVar12;
    undefined8 uVar13;
    int local_18[3];

    puVar12 = ((GameObject*)param_9)->extra;
    iVar5 = FUN_80017a98();
    if (*(char*)((int)puVar12 + 5) == '\0')
    {
        uVar8 = 0;
        if (((*(byte*)&((GameObject*)param_9)->anim.resetHitboxMode & 1) != 0) && (((GameObject*)param_9)->unkF8 == 0))
        {
            *puVar12 = 0;
            puVar12[1] = 0x28;
            FUN_80006ba8(0, 0x100);
            uVar8 = 1;
        }
        *(u8*)((int)puVar12 + 5) = uVar8;
        if (*(char*)((int)puVar12 + 5) != '\0')
        {
            *(u8*)(puVar12 + 3) = 1;
        }
        if (((GameObject*)param_9)->unkF8 == 0)
        {
            ObjHits_EnableObject(param_9);
            *(byte*)&((GameObject*)param_9)->anim.resetHitboxMode = *(byte*)&((GameObject*)param_9)->anim.
                resetHitboxMode & 0xf7;
            ((GameObject*)param_9)->anim.velocityY = -(lbl_803E6A1C * lbl_803DC074 - ((GameObject*)param_9)->anim.
                velocityY);
            ((GameObject*)param_9)->anim.localPosY =
                ((GameObject*)param_9)->anim.velocityY * lbl_803DC074 + ((GameObject*)param_9)->anim.localPosY;
            iVar5 = FUN_800632f4((double)((GameObject*)param_9)->anim.localPosX,
                                 (double)((GameObject*)param_9)->anim.localPosY,
                                 (double)((GameObject*)param_9)->anim.localPosZ, param_9, local_18, 0, 1);
            fVar4 = lbl_803E6A24;
            fVar3 = lbl_803E6A20;
            fVar10 = 0.0;
            iVar11 = 0;
            iVar9 = 0;
            if (0 < iVar5)
            {
                do
                {
                    pfVar6 = *(float**)(local_18[0] + iVar9);
                    if (*(char*)(pfVar6 + 5) != '\x0e')
                    {
                        fVar2 = *pfVar6;
                        if ((((GameObject*)param_9)->anim.localPosY < fVar2) &&
                            ((fVar2 - fVar3 < ((GameObject*)param_9)->anim.localPosY || (iVar11 == 0))))
                        {
                            fVar10 = pfVar6[4];
                            ((GameObject*)param_9)->anim.localPosY = fVar2;
                            ((GameObject*)param_9)->anim.velocityY = fVar4;
                        }
                    }
                    iVar9 = iVar9 + 4;
                    iVar11 = iVar11 + 1;
                    iVar5 = iVar5 + -1;
                }
                while (iVar5 != 0);
            }
            if (fVar10 != 0.0)
            {
                iVar5 = *(int*)((int)fVar10 + 0x58);
                cVar1 = *(char*)(iVar5 + 0x10f);
                *(char*)(iVar5 + 0x10f) = cVar1 + '\x01';
                *(uint*)(iVar5 + cVar1 * 4 + 0x100) = param_9;
            }
        }
    }
    else
    {
        uVar13 = ObjHits_DisableObject(param_9);
        *(byte*)&((GameObject*)param_9)->anim.resetHitboxMode = *(byte*)&((GameObject*)param_9)->anim.resetHitboxMode |
            8;
        uVar7 = FUN_80006c00(0);
        if ((uVar7 & 0x100) != 0)
        {
            *(u8*)(puVar12 + 3) = 0;
            uVar13 = FUN_80006ba8(0, 0x100);
        }
        if (((GameObject*)param_9)->unkF8 == 1)
        {
            *(u8*)((int)puVar12 + 5) = 2;
        }
        if ((*(char*)((int)puVar12 + 5) == '\x02') && (((GameObject*)param_9)->unkF8 == 0))
        {
            *(u8*)((int)puVar12 + 5) = 0;
            *(u8*)(puVar12 + 3) = 0;
        }
        if (*(char*)(puVar12 + 3) != '\0')
        {
            ObjMsg_SendToObject(uVar13, param_2, param_3, param_4, param_5, param_6, param_7, param_8, iVar5, 0x100008,
                                param_9,CONCAT22(puVar12[1], *puVar12), in_r7, in_r8, in_r9, in_r10);
        }
    }
    return;
}


#pragma dont_inline on
void fn_801F20D4(int obj);
#pragma dont_inline reset


#pragma dont_inline on
void fn_801F27E4(int obj);
#pragma dont_inline reset


/*
 * --INFO--
 *
 * Function: FUN_801f2b94
 * EN v1.0 Address: 0x801F2B94
 * EN v1.0 Size: 152b
 * EN v1.1 Address: 0x801F37A8
 * EN v1.1 Size: 124b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801f2b94(short* param_1)
{
    int iVar1;
    double dVar2;

    if (*(char*)(*(int*)(param_1 + 0x5c) + 0xc) == '\x02')
    {
        *param_1 = *param_1 + 0x32;
    }
    iVar1 = FUN_80017a98();
    dVar2 = (double)FUN_8001771c((float*)(iVar1 + 0x18), (float*)(param_1 + 0xc));
    if ((double)lbl_803E6A80 <= dVar2)
    {
        FUN_8000680c((int)param_1, 0x40);
    }
    else
    {
        FUN_80006824((uint)param_1,SFXmn_eggylaugh216);
    }
    return;
}


/* Trivial 4b 0-arg blr leaves. */
void pressureswitch_free(void);

void pressureswitch_hitDetect(void);

void pressureswitch_release(void);

void pressureswitch_initialise(void);

extern f32 lbl_803E5D78;

typedef struct PressureSwitchFlags
{
    u8 unusedHighBit : 1;
    u8 mapBitLatched : 1;
    u8 otherFlags : 6;
} PressureSwitchFlags;

void pressureswitch_init(int* obj, u8* init);

void dll_1FF_free_nop(void);

void dll_1FF_hitDetect_nop(void);

void dll_1FF_release_nop(void);

void dll_1FF_initialise_nop(void);

void wmlasertarget_free(void);

void wmlasertarget_hitDetect(void);

void wmlasertarget_release(void);

void wmlasertarget_initialise(void);

extern void Obj_SetActiveModelIndex(int* obj, int idx);

void wmlasertarget_update(int* obj);

void dll_200_free_nop(void);

void dll_200_hitDetect_nop(void);

void dll_200_release_nop(void);

void dll_200_initialise_nop(void);

void WM_colrise_free(void);

void WM_colrise_hitDetect(void);

void WM_colrise_release(void);

void WM_colrise_initialise(void);

extern void Sfx_PlayFromObject(int obj, int sfxId);
extern void Sfx_StopObjectChannel(int obj, int channel);
extern f32 timeDelta;
extern f32 lbl_803E5DCC;
extern f32 lbl_803E5DD0;
extern f32 lbl_803E5DD4;
extern f32 lbl_803E5DD8;
extern f32 lbl_803E5DDC;
extern f32 lbl_803E5DE0;

void WM_colrise_update(int* obj);

void wmtorch_hitDetect(void);

void wmtorch_release(void);

void wmtorch_initialise(void);

extern f32 lbl_803E5DEC;
extern f32 lbl_803E5DF0;
extern f32 lbl_803E5DF4;
extern f32 lbl_803E5DF8;

void wmtorch_init(u8* obj, u8* params);

void wmtorch_render(int* obj, int p1, int p2, int p3, int p4, s8 visible);

extern void* lbl_803DDC80;

void LaserBeam_initialise(void)
{
    lbl_803DDC80 = Resource_Acquire(0x81, 1);
}

void lightsource_hitDetect(void);

/* 8b "li r3, N; blr" returners. */
int pressureswitch_getExtraSize(void);
int pressureswitch_getObjectTypeId(void);
int dll_1FF_getExtraSize_ret_8(void);
int wmlasertarget_getExtraSize(void);
int wmlasertarget_getObjectTypeId(void);
int dll_200_getExtraSize_ret_40(void);
int dll_200_getObjectTypeId(void);
int WM_colrise_getExtraSize(void);
int WM_colrise_getObjectTypeId(void);
int wmtorch_getExtraSize(void);
int wmtorch_getObjectTypeId(void);
int lightsource_getExtraSize(void);
int lightsource_getObjectTypeId(void);

/* render-with-objRenderFn_8003b8f4 pattern. */
extern f32 lbl_803E5D58;
extern void objRenderFn_8003b8f4(f32);
extern f32 lbl_803E5D90;
extern f32 lbl_803E5DC8;
extern f32 lbl_803E5E08;
extern void queueGlowRender(void* light);

void pressureswitch_render(int p1, int p2, int p3, int p4, int p5, s8 visible);

void wmlasertarget_render(int p1, int p2, int p3, int p4, int p5, s8 visible);

void WM_colrise_render(int p1, int p2, int p3, int p4, int p5, s8 visible);

void lightsource_render(void* obj, int p1, int p2, int p3, int p4, s8 visible);

/* if (o->_X == K) return A; else return B; */
int dll_1FF_getObjectTypeId(int* obj);

/* init pattern: short=-1; byte=0; return 0; */
int PressureSwitch_SeqFn(int obj, int unused, ObjAnimUpdateState* animUpdate);

int WM_colrise_SeqFn(int obj, int unused, ObjAnimUpdateState* animUpdate);

/* fn_X(lbl); lbl = 0; */
void LaserBeam_release(void)
{
    Resource_Release(lbl_803DDC80);
    lbl_803DDC80 = NULL;
}

/* dll_1FF_init: stash (s8 b[0x18] << 8) into a[0] and -0x8000 into a[1]. */
void dll_1FF_init(s16* a, s8* b);

void WM_colrise_init(s16* a, s8* b);


void wmlasertarget_init(char* obj, s8* p);

extern int Obj_GetPlayerObject(void);
extern f32 Vec_distance(f32* a, f32* b);
extern f32 lbl_803E5DE8;

void wmtorch_update(int obj);

extern void Obj_FreeObject(void* o);

void wmtorch_free(int obj, int mode);

extern void ModelLightStruct_free(void* light);

void lightsource_free(int obj);

/* dll_1FF_render: when obj->_f8 implies
 * visible == -1 (else visible != 0), toggle bit 0x1000 of obj->_64->_30
 * based on obj->_b4 == -1, then call objRenderFn_8003b8f4. */
extern f32 lbl_803E5D80;

void dll_1FF_render(int* obj, int p1, int p2, int p3, int p4, s8 visible);

/* dll_200_render: when visible != 0 and
 * gMapEventInterface vtable[0x40] applied to obj->_ac returns 4, gate on
 * GameBit_Get(0x2bd); else render directly via objRenderFn_8003b8f4. */
extern f32 lbl_803E5DC0;

void dll_200_render(int* obj, int p1, int p2, int p3, int p4, s8 visible);

/* dll_200_init: write a function pointer
 * (dll_200_SeqFn) into obj->_bc and prime obj->_b8 (the body block) with
 * fixed bytes, the three float position-quaternion from arg+8/c/10,
 * GameBit_Get(0xd0) latched into b->_24, plus several literal latches. */
extern f32 lbl_803E5D98;

void dll_200_init(int* obj, int* arg);

extern void playerAddRemoveMagic(int player, int amount);
extern void fn_80296474(int player, int a, int b);

int fn_801F2974(int* obj, int unused, ObjAnimUpdateState* animUpdate, int arg3);

#pragma opt_strength_reduction off
int dll_200_SeqFn(int obj, int unused, ObjAnimUpdateState* animUpdate, int arg3);

#pragma opt_strength_reduction off
int fn_801F2974(int* obj, int unused, ObjAnimUpdateState* animUpdate, int arg3);

extern int textureLoadAsset(int id);
extern f32 lbl_803E5D10;

void LaserBeam_free(s16* obj, char* arg)
{
    extern undefined8 ObjMsg_AllocQueue(); /* #57 */
    LaserBeamState* b;

    b = ((GameObject*)obj)->extra;
    ObjMsg_AllocQueue(obj, 2);
    *obj = (s16)((s32)*(s8*)(arg + 0x18) << 8);
    if (*(s16*)(arg + 0x1c) == 0)
    {
        b->firePeriod = (s16)(randomGetRange(-80, 80) + 400);
    }
    else
    {
        b->firePeriod = *(s16*)(arg + 0x1c);
    }
    b->fireTimer = b->firePeriod;
    b->active = 0;
    b->sweepPhase = lbl_803E5D10;
    b->beamKind = *(u8*)(arg + 0x19);
    b->unk2E = 0x118;
    b->emitterSlot = -1;
    if (b->beamKind == 30)
    {
        if (*(void**)&b->texture == NULL)
        {
            b->texture = textureLoadAsset(0x3e9);
        }
    }
    else if (b->beamKind == 1)
    {
        if (*(void**)&b->texture == NULL)
        {
            b->texture = textureLoadAsset(0x23d);
        }
    }
    else if (*(void**)&b->texture == NULL)
    {
        b->texture = textureLoadAsset(0xd9);
    }
}

extern ObjHitReactEntry lbl_80328898[];
void fn_801F2290(int obj);

void dll_200_update(int obj);

typedef struct LightSourceFlagByte
{
    u8 looped : 1;
} LightSourceFlagByte;

void lightsource_update(int obj);

typedef struct Dll1FFSlot
{
    int obj;
} Dll1FFSlot;

typedef struct Dll1FFSlots
{
    u8 pad[0x100];
    Dll1FFSlot slots[3];
    u8 pad2[3];
    u8 count;
} Dll1FFSlots;

void dll_1FF_update(int obj);

typedef struct PswFlags
{
    u8 active : 1;
    u8 latched : 1;
} PswFlags;

#pragma opt_common_subs off
void pressureswitch_update(int obj);
#pragma opt_common_subs reset

typedef struct IntVec3
{
    int a;
    int b;
    int c;
} IntVec3;

typedef struct ArwAttachTarget
{
    f32 x;
    f32 y;
    f32 moveId;
    f32 altMoveId;
    f32 speed;
} ArwAttachTarget;

void fn_801F2290(int obj);
