/*
 * SB_Propeller (DLL 0x01E9) - a spinning propeller blade on General Scales'
 * galleon in the ShipBattle prologue (SB = the retail "ShipBattle" map).
 * The player must shoot out the propellers (after the first deck-gun phase)
 * to keep bringing the galleon down. While the Galleon is intact the
 * propeller emits its loop sfx and spins; once the Galleon's camera/cutscene
 * state lets it take damage the propeller streams smoke, takes hits from the
 * Cloudrunner, and on death plays an explosion and hides itself. The
 * propeller queries the parent Galleon through its anim.dll vtable
 * (offsets 0x20/0x24/0x28) for camera/state info.
 */
#include "main/dll/sbshipheadstate_struct.h"
#include "main/dll/sbpropellerstate_struct.h"
#include "main/effect_interfaces.h"
#include "main/objhits.h"
#include "main/dll/DB/DBstealerworm.h"
#include "main/objlib.h"
#include "main/dll/SB/dll_01E9_sbpropeller.h"

STATIC_ASSERT(sizeof(SBPropellerState) == 0x10);

STATIC_ASSERT(sizeof(SBShipHeadState) == 0x10);

/* anim.seqId tag identifying a live propeller (vs. a placeholder stand-in) */
#define SB_PROPELLER_SEQ_ID 0x69c
/* a second SB object's seqId the propeller ignores when scanning hits */
#define SB_OTHER_SEQ_ID 0x9a

/* propeller sound effects (SB-specific ids, no shared name) */
#define SB_PROPELLER_SFX_LOOP 0x2c6
#define SB_PROPELLER_SFX_HIT 0x2c7
#define SB_PROPELLER_SFX_DESTROYED 0x2c8

extern int randomGetRange(int lo, int hi);
extern u32 DAT_803de8c0;
extern f32 lbl_803E64A8;
extern void Sfx_PlayFromObject(int obj, int sfxId);

extern f32 timeDelta;
extern void Sfx_KeepAliveLoopedObjectSound(u32 obj, u16 sfxId);
extern int DBprotection_getCameraState(u32 g);
extern void Obj_SetModelColorFadeRecursive(int obj, int a, int b, int c, int d, int e);
extern void* Obj_GetPlayerObject(void);
extern u8 framesThisStep;
extern void spawnExplosion(int obj, f32 s, int a, int b, int c, int d, int e, int f, int g);
extern f32 lbl_803E5810;
extern f32 lbl_803E5814;
extern f32 lbl_803E5818;
extern f32 lbl_803E581C;
extern f32 lbl_803E5820;
extern f32 lbl_803E5824;
extern u32 lbl_803DDC40;
extern void objRenderModelAndHitVolumes(int obj, int p2, int p3, int p4, int p5, f32 scale);

void SB_Propeller_update(int obj)
{
    ObjAnimComponent* objAnim;
    int camA;
    int camB;
    int camC;
    int parentTimer;
    GameObject* o;
    int i;
    int j;
    int hit;
    SBPropellerState* state;
    struct
    {
        u8 pad[6];
        u16 mode;
        f32 a;
        f32 b;
        f32 c;
        f32 d;
    } stk;

    objAnim = (ObjAnimComponent*)obj;
    o = (GameObject*)obj;
    state = o->extra;
    camA = SB_GALLEON_VTBL(*(int*)&objAnim->parent)->getStage(*(int*)&objAnim->parent);
    camB = SB_GALLEON_VTBL(*(int*)&objAnim->parent)->getPhase(*(int*)&objAnim->parent);
    if (((state->health != 0) && (camB < 6)) && (objAnim->seqId != SB_PROPELLER_SEQ_ID))
    {
        Sfx_KeepAliveLoopedObjectSound(obj, SB_PROPELLER_SFX_LOOP);
    }
    camC = DBprotection_getCameraState(*(int*)&objAnim->parent);
    if ((camC < 2) && (state->health <= 0))
    {
        state->smokeTimer = state->smokeTimer - timeDelta;
        if (state->smokeTimer <= lbl_803E5814)
        {
            f32 spd;
            for (i = randomGetRange(10, 0x19), spd = lbl_803E5810; i != 0; i--)
            {
                stk.b = objAnim->worldPosX;
                stk.c = objAnim->worldPosY;
                stk.d = objAnim->worldPosZ;
                stk.a = spd;
                (*gPartfxInterface)->spawnObject((void*)obj, 0x9f, stk.pad, 0x200001, -1, NULL);
            }
            state->smokeTimer = (f32)(int)randomGetRange(0x5a, 0xf0);
        }
        if ((2 < camA) && (objAnim->bankIndex == 1))
        {
            stk.a = lbl_803E5818;
            stk.mode = 0xc0a;
            ObjPath_GetPointWorldPosition(obj, 0, &stk.b, &stk.c, &stk.d, 0);
            stk.b = stk.b - objAnim->worldPosX;
            stk.c = stk.c - objAnim->worldPosY;
            stk.d = stk.d - objAnim->worldPosZ;
            for (j = 0; j < framesThisStep; j++)
            {
                (*gPartfxInterface)->spawnObject((void*)obj, 0x7aa, stk.pad, 2, -1, NULL);
            }
        }
    }
    if (objAnim->parent != NULL)
    {
        parentTimer = ((GameObject*)objAnim->parent)->unkF4;
        if ((objAnim->seqId != SB_PROPELLER_SEQ_ID) && (parentTimer < 4))
        {
            state->spinBlend = state->spinRate / lbl_803E581C;
            if (state->spinBlend < lbl_803E5814)
            {
                state->spinBlend = -state->spinBlend;
            }
            if (state->spinBlend < *(f32*)&lbl_803E5820)
            {
                state->spinBlend = lbl_803E5820;
            }
        }
        o->unkF4 = o->unkF4 - framesThisStep;
        if (o->unkF4 < 0)
        {
            o->unkF4 = 0;
        }
        if (((((((camB == 1) && (ObjHits_GetPriorityHit(obj, &hit, 0, 0) != 0))
                        && (o->unkF4 == 0))
                    && (((void*)hit != NULL && ((void*)hit != (void*)Obj_GetPlayerObject()))))
                && ((((GameObject*)hit)->anim.seqId != SB_PROPELLER_SEQ_ID
                    && ((((GameObject*)hit)->anim.seqId != SB_OTHER_SEQ_ID
                        && ((o->unkF4 = 0x14, objAnim->parent != NULL)))))))
            && ((camA == 2 || (camA == 5)))) && (objAnim->seqId == SB_PROPELLER_SEQ_ID))
        {
            Obj_SetModelColorFadeRecursive(obj, 0xf, 200, 0, 0, 1);
            Sfx_PlayFromObject(obj, SB_PROPELLER_SFX_HIT);
            state->health -= 1;
            if (state->health <= 0)
            {
                state->health = 0;
                SB_GALLEON_VTBL(*(int*)&objAnim->parent)->onPartDestroyed(*(int*)&objAnim->parent);
                ObjHits_DisableObject(obj);
                objAnim->flags = objAnim->flags | OBJANIM_FLAG_HIDDEN;
                spawnExplosion(obj, lbl_803E5824, 1, 1, 1, 0, 1, 1, 0);
                Sfx_PlayFromObject(obj, SB_PROPELLER_SFX_DESTROYED);
            }
        }
        if (o->unkF4 == 0)
        {
            ((ObjHitsPriorityState*)objAnim->hitReactState)->hitVolumePriority = 6;
            ((ObjHitsPriorityState*)objAnim->hitReactState)->hitVolumeId = 1;
            ((ObjHitsPriorityState*)objAnim->hitReactState)->objectHitMask = 0x10;
            ((ObjHitsPriorityState*)objAnim->hitReactState)->skeletonHitMask = 0x10;
        }
        else
        {
            ((ObjHitsPriorityState*)objAnim->hitReactState)->objectPairPriority = 0;
        }
        objAnim->rotZ = -(state->spinRate * timeDelta - (
            f32)objAnim->rotZ);
    }
}

void SB_Propeller_init(GameObject* obj, int placement)
{
    ObjAnimComponent* objAnim;
    u32 randVal;
    SBPropellerState* state;

    objAnim = (ObjAnimComponent*)obj;
    state = obj->extra;
    randVal = randomGetRange(0x5a, 0xf0);
    state->smokeTimer = (f32)(s32)(randVal);
    state->spinBlend = lbl_803E64A8;
    state->spinRate = 1200;
    state->health = 4;
    objAnim->bankIndex = (char)*(s16*)(placement + 0x1a);
    if (objAnim->seqId != SB_PROPELLER_SEQ_ID)
    {
        DAT_803de8c0 = (u32)obj;
    }
    return;
}

int SB_Propeller_getExtraSize(void) { return sizeof(SBPropellerState); }

u32 fn_801E2570(void) { return lbl_803DDC40; }

void SB_Propeller_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0) objRenderModelAndHitVolumes(p1, p2, p3, p4, p5, lbl_803E5810);
}

void SB_Propeller_hitDetect(GameObject* obj)
{
    GameObject* o = obj;
    if (o->anim.seqId != SB_PROPELLER_SEQ_ID) return;
    o->anim.rotZ = *(s16*)(lbl_803DDC40 + 4);
}

