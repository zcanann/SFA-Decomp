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
#include "main/audio/sfx_ids.h"
#include "main/effect_interfaces.h"
#include "main/objlib.h"
#include "main/dll/DB/DBstealerworm.h"

#define SBSHIPHEAD_OBJGROUP 3

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

extern int randomGetRange(int lo, int hi);
extern void Sfx_PlayFromObject(int obj, int sfxId);
extern f32 timeDelta;
extern int DBprotection_getCameraState(u32 g);
extern void Obj_SetModelColorFadeRecursive(int obj, int a, int b, int c, int d, int e);
extern int Obj_GetPlayerObject(void);
extern u8 framesThisStep;
extern u32 getSbGalleon(void);
extern f32 Vec_distance(f32* a, f32* b);
extern void Sfx_StopObjectChannel(u32 obj, u32 channel);
extern u8 Obj_IsLoadingLocked(void);
extern void Obj_GetWorldPosition(int obj, f32* x, f32* y, f32* z);
extern void* Obj_AllocObjectSetup(int size, int b);
extern int Obj_SetupObject(u8* setup, int a, int b, int c, int d);
extern u8 gSbShipHeadHasFiredFireball;
extern int gSbShipHeadPrevGalleonPhase;
extern f32 sqrtf(f32);

/* .sdata2 constant pool */
static const f32 lbl_803E5830 = 1.0f;
static const f32 lbl_803E5834 = 0.0f;
static const f32 lbl_803E5838 = 10.0f;
static const f32 lbl_803E583C = 3.0f;
static const f32 gSbShipHeadHissSfxDistance = 400.0f;
static const f32 lbl_803E5844 = 0.5f;
static const f32 lbl_803E5848 = 50.0f;
static const f32 lbl_803E584C = 300.0f;
static const f32 gSbShipHeadFireballSpeed = 30.0f;
static const f32 lbl_803E5854 = 100.0f;
static const f32 lbl_803E5858 = 45.0f;
static const f32 gSbShipHeadAnimAdvanceRate = 0.005f;
static const f64 lbl_803E5860 = 4503601774854144.0;

int SB_ShipHead_getExtraSize(void) { return sizeof(SBShipHeadState); }
int SB_ShipHead_getObjectTypeId(void) { return 0x1; }

u32 getSbGalleon(void);

void SB_ShipHead_free(int x) { ObjGroup_RemoveObject((u32)x, SBSHIPHEAD_OBJGROUP); }

void SB_ShipHead_render(GameObject* obj, int p2, int p3, int p4, int p5, s8 visible)
{
extern void objRenderModelAndHitVolumes(GameObject* obj, int p2, int p3, int p4, int p5, f32 scale);
    int phase;
    int parent;
    SBShipHeadState* state;
    GameObject* o;
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

    o = (GameObject*)obj;
    if (visible != 0)
    {
        state = o->extra;
        objRenderModelAndHitVolumes(obj, p2, p3, p4, p5, lbl_803E5830);
        parent = *(int*)&o->anim.parent;
        if ((((void*)parent != NULL && (((GameObject*)parent)->anim.seqId == SB_GALLEON_SEQID_FIRING)) &&
            (phase = SB_GALLEON_VTBL(parent)->getDamagePhase(parent),
                phase != 0)) && (phase != 2))
        {
            state->swayA = state->swayA - timeDelta;
            if (state->swayA <= lbl_803E5834)
            {
                state->swayA += lbl_803E5838;
            }
            state->swayB = state->swayB - timeDelta;
            if (state->swayB <= lbl_803E5834)
            {
                state->swayB += lbl_803E5830;
            }
            stk.a = lbl_803E583C;
            stk.mode = 0xc0a;
            ObjPath_GetPointWorldPosition((int)obj, 0xd, &stk.b, &stk.c, &stk.d, 0);
            stk.b = stk.b - o->anim.worldPosX;
            stk.c = stk.c - o->anim.worldPosY;
            stk.d = stk.d - o->anim.worldPosZ;
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
    GameObject* o;

    o = (GameObject*)obj;
    fireCue = 0;
    player = Obj_GetPlayerObject();
    galleon = *(u8**)&o->anim.parent;
    if (galleon == 0)
    {
        return;
    }
        camState = DBprotection_getCameraState(getSbGalleon());
        if (camState == 2)
        {
            if (Vec_distance((void*)(player + 0x18), &o->anim.worldPosX) < gSbShipHeadHissSfxDistance)
            {
                Sfx_PlayFromObject(obj, SFXfend_rob_armin);
            }
            else
            {
                Sfx_StopObjectChannel(obj, 0x40);
            }
        }
        galleonPhase = ((GameObject*)galleon)->unkF4;
        hs = o->extra;
        if (*(void**)&hs->target == 0)
        {
            int* arr = ObjList_GetObjects(&start, &end);
            for (i = start; i < end; i++)
            {
                if (((GameObject*)arr[i])->anim.seqId == SB_SHIPHEAD_TARGET_SEQID)
                {
                    hs->target = arr[i];
                    i = end;
                }
            }
        }
        if ((int)ObjMsg_Pop((void*)obj, (u32*)&msg, (u32*)tmp2, (u32*)&tmp3) != 0)
        {
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
        if ((SB_GALLEON_VTBL(galleon)->getPhase((int)galleon) >= 2)
            && (o->unkF8 <= 0) && (((u32)(galleonPhase - 3) <= 1 || (galleonPhase == 5)))
            && (ObjHits_GetPriorityHit(obj, &hit, 0, 0) != 0)
            && (((GameObject*)hit)->anim.seqId != SB_FIREBALL_OBJID))
        {
            Obj_SetModelColorFadeRecursive(obj, 0xf, 200, 0, 0, 1);
            Sfx_PlayFromObject(obj, SFXen_sbalhis6);
            hs->health -= 1;
            if (hs->health <= 0)
            {
                SB_GALLEON_VTBL(galleon)->onPartDestroyed((int)galleon);
                o->unkF8 = 300;
                ObjHits_DisableObject((u32)obj);
            }
        }
        if (0 < o->unkF8)
        {
            o->unkF8 = o->unkF8 - framesThisStep;
        }
        if (galleonPhase == 8)
        {
            o->unkF4 = o->unkF4 + 1;
            if (10 < o->unkF4)
            {
                o->unkF4 = 0;
            }
        }
        if ((galleonPhase == 5) && (gSbShipHeadPrevGalleonPhase != 5))
        {
            ObjAnim_SetCurrentMove(obj, 1, lbl_803E5834, 0);
            gSbShipHeadHasFiredFireball = 0;
        }
        if ((((o->anim.currentMove == 1) && (o->anim.
                currentMoveProgress >= lbl_803E5844))
            && (gSbShipHeadHasFiredFireball == 0)) && (Obj_IsLoadingLocked() != 0))
        {
            gSbShipHeadHasFiredFireball = 1;
            o->unkF4 = o->unkF4 + framesThisStep;
            Sfx_PlayFromObject(obj, SFXen_scrap1_c);
            o->anim.localPosY += lbl_803E5848;
            o->anim.localPosZ = o->anim.localPosZ - lbl_803E584C;
            Obj_GetWorldPosition(obj, &px, &py, &pz);
            o->anim.localPosY = o->anim.localPosY - lbl_803E5848;
            o->anim.localPosZ += lbl_803E584C;
            setup = Obj_AllocObjectSetup(0x18, SB_FIREBALL_OBJID);
            setup[6] = 0xff;
            setup[7] = 0xff;
            setup[4] = 2;
            setup[5] = 1;
            ((ObjPlacement*)setup)->posX = px;
            ((ObjPlacement*)setup)->posY = py;
            ((ObjPlacement*)setup)->posZ = pz;
            proj = Obj_SetupObject(setup, 5, -1, -1, 0);
            ddx = ((GameObject*)player)->anim.worldPosX - ((GameObject*)proj)->anim.localPosX;
            ddy = (((GameObject*)player)->anim.worldPosY - gSbShipHeadFireballSpeed) - ((GameObject*)proj)->anim.localPosY;
            ddz = ((GameObject*)player)->anim.worldPosZ - ((GameObject*)proj)->anim.localPosZ;
            s = gSbShipHeadFireballSpeed / sqrtf(ddz * ddz + (ddx * ddx + ddy * ddy));
            ((GameObject*)proj)->anim.velocityX = ddx * s;
            ((GameObject*)proj)->anim.velocityY = ddy * s;
            ((GameObject*)proj)->anim.velocityZ = ddz * s;
            ((GameObject*)proj)->unkF4 = 0x78;
            ((GameObject*)proj)->unkF8 = hs->target;
        }
        if ((fireCue == 1) && (Obj_IsLoadingLocked() != 0))
        {
            Sfx_PlayFromObject(obj, SFXen_scrap1_c);
            player = Obj_GetPlayerObject();
            setup = Obj_AllocObjectSetup(0x18, SB_PROJECTILE_OBJID);
            ((ObjPlacement*)setup)->posX = lbl_803E5854 + ((GameObject*)player)->anim.worldPosX;
            ((ObjPlacement*)setup)->posY = lbl_803E5848 + (((GameObject*)player)->anim.worldPosY + (f32)(int)
            randomGetRange(-6, 6)
            )
            ;
            ((ObjPlacement*)setup)->posZ = lbl_803E5858 + (((GameObject*)player)->anim.worldPosZ + (f32)(int)
            randomGetRange(-6, 6)
            )
            ;
            setup[4] = 2;
            setup[5] = 1;
            setup[6] = 0xff;
            setup[7] = 0xff;
            Obj_SetupObject(setup, 5, -1, -1, 0);
        }
        proj = ((int (*)(int, f32, f32, void*))ObjAnim_AdvanceCurrentMove)(obj, gSbShipHeadAnimAdvanceRate, timeDelta, NULL);
        if ((o->anim.currentMove == 1) && (proj != 0))
        {
            ObjAnim_SetCurrentMove(obj, 0, lbl_803E5834, 0);
        }
        gSbShipHeadPrevGalleonPhase = galleonPhase;
}

void SB_ShipHead_init(int obj)
{
    SBShipHeadState* state = ((GameObject*)obj)->extra;
    ObjGroup_AddObject((u32)obj, SBSHIPHEAD_OBJGROUP);
    ObjMsg_AllocQueue((void*)obj, 10);
    state->health = 4;
    state->swayB += lbl_803E5830;
    state->swayA += lbl_803E5838;
}

