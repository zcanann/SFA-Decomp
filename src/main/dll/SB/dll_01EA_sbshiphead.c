/*
 * SB_ShipHead (DLL 0x1EA) - the figurehead/prow of General Scales' galleon
 * in the ShipBattle prologue (SB = the retail "ShipBattle" map). While the
 * parent Galleon's camera/cutscene state allows it the head plays its hiss
 * loop near the player, accepts hits (4 HP), spits homing fireballs
 * (SB_FireBall) along its rigging path and lobs projectiles at the
 * Cloudrunner on cue, advancing its animation each frame. State lives in the
 * SBShipHeadState extra block. The Galleon is queried through its anim.dll
 * vtable (slots 0x20/0x28/0x2c) and through DBprotection_getCameraState.
 */
#include "main/obj_placement.h"
#include "main/dll/sbshipheadstate_struct.h"
#include "main/dll/sbpropellerstate_struct.h"
#include "main/game_object.h"
#include "main/audio/sfx_ids.h"
#include "main/effect_interfaces.h"
#include "main/mapEventTypes.h"
#include "main/objseq.h"
#include "main/dll/DB/DBstealerworm.h"
#include "main/dll/DB/sbgalleon_state.h"

STATIC_ASSERT(sizeof(SBPropellerState) == 0x10);

STATIC_ASSERT(sizeof(SBShipHeadState) == 0x10);

/* parent Galleon anim.seqId variants */
#define SB_GALLEON_SEQID_FIRING 0x8e
/* object type id (anim.seqId) of the galleon-side target object the head tracks */
#define SB_SHIPHEAD_TARGET_SEQID 0x8c
/* object type id of the head's own homing-fireball projectile */
#define SB_FIREBALL_OBJID 0x114
/* object type id of the lobbed projectile spawned on the firing cue */
#define SB_PROJECTILE_OBJID 0x138

/* parent Galleon anim.dll vtable slots */
#define GALLEON_VT_ON_HEAD_DESTROYED 0x20
#define GALLEON_VT_GET_CAM_B 0x28
#define GALLEON_VT_GET_PHASE 0x2c

extern u32 randomGetRange(int min, int max);
extern u32 ObjHits_DisableObject();
extern int ObjHits_GetPriorityHit();
extern u64 ObjGroup_RemoveObject();
extern u32 ObjGroup_AddObject();
extern int ObjMsg_Pop();

extern EffectInterface** gPartfxInterface;

extern int ObjList_GetObjects(int* start, int* end);
extern void Sfx_PlayFromObject(int obj, int sfxId);
extern f32 timeDelta;

extern int DBprotection_getCameraState(u32 g);
extern void Obj_SetModelColorFadeRecursive(int obj, int a, int b, int c, int d, int e);
extern int Obj_GetPlayerObject(void);
extern u8 framesThisStep;
extern int ObjPath_GetPointWorldPosition(int obj, int idx, f32* x, f32* y, f32* z, int p);

extern u32 getSbGalleon(void);
extern f32 Vec_distance(void* a, void* b);
extern void Sfx_StopObjectChannel(int obj, int ch);
extern u8 Obj_IsLoadingLocked(void);
extern void Obj_GetWorldPosition(int obj, f32* x, f32* y, f32* z);
extern u8* Obj_AllocObjectSetup(int size, int objId);
extern int Obj_SetupObject(u8* setup, int a, int b, int c, int d);
extern u8 lbl_803DC090;
extern int lbl_803DDC48;
extern f32 lbl_803E5834;
extern f32 lbl_803E5840;
extern f32 lbl_803E5844;
extern f32 lbl_803E5848;
extern f32 lbl_803E584C;
extern f32 lbl_803E5850;
extern f32 lbl_803E5854;
extern f32 lbl_803E5858;
extern f32 lbl_803E585C;
extern f32 sqrtf(f32);
extern void ObjMsg_AllocQueue(int obj, int n);
extern f32 lbl_803E5830;
extern f32 lbl_803E5838;
extern f32 lbl_803E583C;

void SB_ShipHead_render(int obj, int p2, int p3, int p4, int p5, s8 visible)
{
    extern void objRenderFn_8003b8f4(f32);
    int phase;
    int parent;
    SBShipHeadState* state;
    u8 i;
    struct
    {
        u8 pad[6];
        u16 mode;
        f32 a;
        f32 b;
        f32 c;
        f32 d;
    } stk;

    if (visible != 0)
    {
        state = ((GameObject*)obj)->extra;
        objRenderFn_8003b8f4(lbl_803E5830);
        parent = *(int*)&((GameObject*)obj)->anim.parent;
        if ((((void*)parent != NULL && (((GameObject*)parent)->anim.seqId == SB_GALLEON_SEQID_FIRING)) &&
            (phase = (**(int (**)(int))(**(int**)&((GameObject*)parent)->anim.dll + GALLEON_VT_GET_PHASE))(parent),
                phase != 0)) && (phase != 2))
        {
            state->swayA = state->swayA - timeDelta;
            if (state->swayA <= lbl_803E5834)
            {
                state->swayA = state->swayA + lbl_803E5838;
            }
            state->swayB = state->swayB - timeDelta;
            if (state->swayB <= lbl_803E5834)
            {
                state->swayB = state->swayB + lbl_803E5830;
            }
            stk.a = lbl_803E583C;
            stk.mode = 0xc0a;
            ObjPath_GetPointWorldPosition(obj, 0xd, &stk.b, &stk.c, &stk.d, 0);
            stk.b = stk.b - ((GameObject*)obj)->anim.worldPosX;
            stk.c = stk.c - ((GameObject*)obj)->anim.worldPosY;
            stk.d = stk.d - ((GameObject*)obj)->anim.worldPosZ;
            for (i = 0; i < framesThisStep; i++)
            {
                (*gPartfxInterface)->spawnObject((void*)obj, 0x7aa, stk.pad, 2, -1, NULL);
            }
        }
    }
    return;
}

void SB_ShipHead_update(int obj)
{
    f32 ddx;
    f32 ddy;
    f32 ddz;
    f32 s;
    int player;
    u8 fireCue;
    u8* galleon;
    SBShipHeadState* hs;
    int galleonPhase;
    int camState;
    int i;
    int proj;
    u8* setup;
    int hit;
    int tmp3;
    f32 px;
    f32 py;
    f32 pz;
    int start;
    int end;
    int msg;
    int tmp2[2];

    fireCue = 0;
    player = Obj_GetPlayerObject();
    galleon = *(u8**)&((GameObject*)obj)->anim.parent;
    if (galleon == 0)
    {
        return;
    }
        camState = DBprotection_getCameraState(getSbGalleon());
        if (camState == 2)
        {
            if (Vec_distance((void*)(player + 0x18), (void*)&((GameObject*)obj)->anim.worldPosX) < lbl_803E5840)
            {
                Sfx_PlayFromObject(obj, SFXfend_rob_armin);
            }
            else
            {
                Sfx_StopObjectChannel(obj, 0x40);
            }
        }
        galleonPhase = ((GameObject*)galleon)->unkF4;
        hs = ((GameObject*)obj)->extra;
        if (*(void**)&hs->target == 0)
        {
            int* arr = (int*)ObjList_GetObjects(&start, &end);
            for (i = start; i < end; i++)
            {
                if (*(s16*)(arr[i] + 0x46) == SB_SHIPHEAD_TARGET_SEQID)
                {
                    hs->target = arr[i];
                    i = end;
                }
            }
        }
        if (ObjMsg_Pop(obj, &msg, tmp2, &tmp3) != 0)
        {
            /* object-message opcodes raised by the galleon sequence */
            switch (msg)
            {
            case 0x130001:
                break;
            case 0x130002:
                fireCue = 1;
                break;
            case 0x130003:
                fireCue = 2;
                break;
            }
        }
        if (((**(int (**)(u8*))(**(int**)&((GameObject*)galleon)->anim.dll + GALLEON_VT_GET_CAM_B))(galleon) >= 2)
            && (((GameObject*)obj)->unkF8 <= 0) && (((uint)(galleonPhase - 3) <= 1 || (galleonPhase == 5)))
            && (ObjHits_GetPriorityHit(obj, &hit, 0, 0) != 0)
            && (*(s16*)(hit + 0x46) != SB_FIREBALL_OBJID))
        {
            Obj_SetModelColorFadeRecursive(obj, 0xf, 200, 0, 0, 1);
            Sfx_PlayFromObject(obj, SFXen_sbalhis6);
            hs->health -= 1;
            if (hs->health <= 0)
            {
                (**(void (**)(u8*))(**(int**)&((GameObject*)galleon)->anim.dll + GALLEON_VT_ON_HEAD_DESTROYED))(galleon);
                ((GameObject*)obj)->unkF8 = 300;
                ObjHits_DisableObject(obj);
            }
        }
        if (0 < ((GameObject*)obj)->unkF8)
        {
            ((GameObject*)obj)->unkF8 = ((GameObject*)obj)->unkF8 - framesThisStep;
        }
        if (galleonPhase == 8)
        {
            ((GameObject*)obj)->unkF4 = ((GameObject*)obj)->unkF4 + 1;
            if (10 < ((GameObject*)obj)->unkF4)
            {
                ((GameObject*)obj)->unkF4 = 0;
            }
        }
        if ((galleonPhase == 5) && (lbl_803DDC48 != 5))
        {
            ObjAnim_SetCurrentMove(obj, 1, lbl_803E5834, 0);
            lbl_803DC090 = 0;
        }
        if ((((((GameObject*)obj)->anim.currentMove == 1) && (((GameObject*)obj)->anim.
                currentMoveProgress >= lbl_803E5844))
            && (lbl_803DC090 == 0)) && (Obj_IsLoadingLocked() != 0))
        {
            lbl_803DC090 = 1;
            ((GameObject*)obj)->unkF4 = ((GameObject*)obj)->unkF4 + framesThisStep;
            Sfx_PlayFromObject(obj, SFXen_scrap1_c);
            ((GameObject*)obj)->anim.localPosY = ((GameObject*)obj)->anim.localPosY + lbl_803E5848;
            ((GameObject*)obj)->anim.localPosZ = ((GameObject*)obj)->anim.localPosZ - lbl_803E584C;
            Obj_GetWorldPosition(obj, &px, &py, &pz);
            ((GameObject*)obj)->anim.localPosY = ((GameObject*)obj)->anim.localPosY - lbl_803E5848;
            ((GameObject*)obj)->anim.localPosZ = ((GameObject*)obj)->anim.localPosZ + lbl_803E584C;
            setup = Obj_AllocObjectSetup(0x18, SB_FIREBALL_OBJID);
            setup[6] = 0xff;
            setup[7] = 0xff;
            setup[4] = 2;
            setup[5] = 1;
            ((ObjPlacement*)setup)->posX = px;
            ((ObjPlacement*)setup)->posY = py;
            ((ObjPlacement*)setup)->posZ = pz;
            proj = Obj_SetupObject(setup, 5, -1, -1, 0);
            ddx = *(f32*)(player + 0x18) - *(f32*)(proj + 0xc);
            ddy = (*(f32*)(player + 0x1c) - lbl_803E5850) - *(f32*)(proj + 0x10);
            ddz = *(f32*)(player + 0x20) - *(f32*)(proj + 0x14);
            s = lbl_803E5850 / sqrtf(ddz * ddz + (ddx * ddx + ddy * ddy));
            *(f32*)(proj + 0x24) = ddx * s;
            *(f32*)(proj + 0x28) = ddy * s;
            *(f32*)(proj + 0x2c) = ddz * s;
            *(int*)(proj + 0xf4) = 0x78;
            *(int*)(proj + 0xf8) = hs->target;
        }
        if ((fireCue == 1) && (Obj_IsLoadingLocked() != 0))
        {
            Sfx_PlayFromObject(obj, SFXen_scrap1_c);
            player = Obj_GetPlayerObject();
            setup = Obj_AllocObjectSetup(0x18, SB_PROJECTILE_OBJID);
            ((ObjPlacement*)setup)->posX = lbl_803E5854 + *(f32*)(player + 0x18);
            ((ObjPlacement*)setup)->posY = lbl_803E5848 + (*(f32*)(player + 0x1c) + (f32)(int)
            randomGetRange(-6, 6)
            )
            ;
            ((ObjPlacement*)setup)->posZ = lbl_803E5858 + (*(f32*)(player + 0x20) + (f32)(int)
            randomGetRange(-6, 6)
            )
            ;
            setup[4] = 2;
            setup[5] = 1;
            setup[6] = 0xff;
            setup[7] = 0xff;
            Obj_SetupObject(setup, 5, -1, -1, 0);
        }
        proj = ((int (*)(int, f32, f32, void*))ObjAnim_AdvanceCurrentMove)(obj, lbl_803E585C, timeDelta, NULL);
        if ((((GameObject*)obj)->anim.currentMove == 1) && (proj != 0))
        {
            ObjAnim_SetCurrentMove(obj, 0, lbl_803E5834, 0);
        }
        lbl_803DDC48 = galleonPhase;
}

void SB_Galleon_release(void);

int SB_ShipHead_getExtraSize(void) { return sizeof(SBShipHeadState); }
int SB_ShipHead_getObjectTypeId(void) { return 0x1; }
int SB_ShipMast_getExtraSize(void);

u32 getSbGalleon(void);

void SB_ShipHead_free(int x) { ObjGroup_RemoveObject(x, 0x3); }

void SB_Propeller_hitDetect(int obj);

void SB_ShipHead_init(int obj)
{
    SBShipHeadState* state = ((GameObject*)obj)->extra;
    ObjGroup_AddObject(obj, 3);
    ObjMsg_AllocQueue(obj, 10);
    state->health = 4;
    state->swayB = state->swayB + lbl_803E5830;
    state->swayA = state->swayA + lbl_803E5838;
}

void SB_ShipGun_render(int obj, int p2, int p3, int p4, int p5, s8 visible);
