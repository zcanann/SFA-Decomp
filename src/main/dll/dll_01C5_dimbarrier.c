/* === moved from main/dll/DIM/dimsnowball_init.c [801B13E8-801B13F0) (TU re-split, docs/boundary_audit.md) === */
#include "ghidra_import.h"








int dimsnowball1c2_getExtraSize(void);

#include "ghidra_import.h"
#include "main/effect_interfaces.h"
#include "main/game_object.h"
#include "main/audio/sfx_ids.h"
#include "main/dll/DIM/DIMExplosion.h"

typedef struct DimbarrierPlacement
{
    u8 pad0[0x1E - 0x0];
    s16 unk1E;
} DimbarrierPlacement;


typedef struct DimgatePlacement
{
    u8 pad0[0x1E - 0x0];
    s16 unk1E;
} DimgatePlacement;


typedef struct Dimsnowball1c2State
{
    s8 unk0;
    u8 pad1[0x2 - 0x1];
    s16 unk2;
    u8 pad4[0x8 - 0x4];
} Dimsnowball1c2State;


typedef struct DimicewallPlacement
{
    u8 pad0[0x14 - 0x0];
    s32 unk14;
    u8 pad18[0x19 - 0x18];
    s8 unk19;
    u8 pad1A[0x1E - 0x1A];
    s16 unk1E;
} DimicewallPlacement;


typedef struct Dimsnowball1c2Placement
{
    u8 pad0[0x4 - 0x0];
    u8 unk4;
    u8 unk5;
    u8 unk6;
    u8 unk7;
    u8 pad8[0x14 - 0x8];
    s32 unk14;
    u8 pad18[0x19 - 0x18];
    s8 unk19;
    u8 unk1A;
    u8 unk1B;
    s8 unk1C;
    u8 pad1D[0x1E - 0x1D];
    s16 unk1E;
} Dimsnowball1c2Placement;


typedef struct DimicewallState
{
    u8 pad0[0x1 - 0x0];
    u8 unk1;
    s16 unk2;
    u8 pad4[0x8 - 0x4];
} DimicewallState;




typedef struct DIMwooddoorUpdateFallingDebrisState
{
    u8 pad0[0x1 - 0x0];
    u8 unk1;
    s16 unk2;
    u8 pad4[0x5 - 0x4];
    s8 hitboxRadius;
    s8 hitVolumeSlot;
    u8 unk7;
    u8 state;
    s8 rotZRate;
    s8 rotYRate;
    s8 rotXRate;
    u8 padC[0x10 - 0xC];
} DIMwooddoorUpdateFallingDebrisState;


extern uint GameBit_Get(int eventId);
extern undefined4 GameBit_Set(int eventId, int value);
extern u32 randomGetRange(int min, int max);
extern void ObjHitbox_SetStateIndex(int obj, ObjHitsPriorityState* hitState, int stateIndex);


/* Trivial 4b 0-arg blr leaves. */
void dimsnowball1c2_free(void);

void dimsnowball1c2_hitDetect(void);

void dimsnowball1c2_release(void);

void dimsnowball1c2_initialise(void);

void dimgate_free(void);

void dimgate_hitDetect(void);

void dimgate_release(void);

void dimgate_initialise(void);

void dimbarrier_free(void)
{
}

void dimbarrier_hitDetect(void)
{
}

void dimbarrier_release(void)
{
}

void dimbarrier_initialise(void)
{
}

/* 8b "li r3, N; blr" returners. */
int dimsnowball1c2_getObjectTypeId(void);
int dimgate_SeqFn(void);
int dimgate_getExtraSize(void);
int dimgate_getObjectTypeId(void);
int dimicewall_getExtraSize(void);
int dimbarrier_getExtraSize(void) { return 0x4; }
int dimbarrier_getObjectTypeId(void) { return 0x0; }

/* render-with-objRenderFn_8003b8f4 pattern. */
extern f32 lbl_803E4860;
extern void objRenderFn_8003b8f4(f32);
extern f32 lbl_803E4878;
extern f32 lbl_803E4898;

void dimsnowball1c2_render(int p1, int p2, int p3, int p4, int p5, s8 visible);

void dimgate_render(int p1, int p2, int p3, int p4, int p5, s8 visible);

void dimbarrier_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0) objRenderFn_8003b8f4(lbl_803E4898);
}

void dimsnowball1c2_init(int obj, u8* p);

void dimicewall_init(int obj, s8* p);

void dimgate_init(int obj, s8* p_unused_passthrough);

void dimbarrier_init(int obj, s8* p)
{
    char* inner;
    *(s16*)obj = (s16)((s32)p[0x18] << 8);
    ((GameObject*)obj)->objectFlags |= 0x6000;
    inner = ((GameObject*)obj)->extra;
    inner[3] = 1;
    inner[2] = 0;
    if (GameBit_Get(*(s16*)(p + 0x1e)) != 0)
    {
        ObjHitsPriorityState* hitState;
        inner[3] = 0;
        hitState = (ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState;
        hitState->flags &= ~1;
        ((GameObject*)obj)->anim.alpha = 0;
        inner[2] = 2;
    }
}

int fn_801B17F4(int obj, int delta);

/* dimgate_update: open the gate (hitbox state 1->2) once a type-399 object is
 * present in the trigger list, latching the gamebit. */
void dimgate_update(int* obj);

extern int Sfx_PlayFromObject(int obj, int sfx);
extern u8 framesThisStep;

/* dimbarrier_update: while a live type-470 object is in the list, count down the
 * arm timer; on expiry fade the barrier out and latch its gamebit. */
void dimbarrier_update(int* obj)
{
    int* def = *(int**)&((GameObject*)obj)->anim.placementData;
    int* extra = ((GameObject*)obj)->extra;
    switch (*(u8*)((char*)extra + 2))
    {
    case 0:
        {
            int* list = *(int**)((char*)obj + 0x58);
            int found = 0;
            int i;
            for (i = 0; i < *(s8*)((char*)list + 0x10f); i++)
            {
                int* entry = *(int**)((char*)list + 0x100 + i * 4);
                if (*(s16*)((char*)entry + 0x46) == 470 &&
                    *(u8*)((char*)*(int**)((char*)entry + 0xb8) + 4) != 0)
                {
                    found = 1;
                    break;
                }
            }
            if (found)
            {
                s8 v = *(u8*)((char*)extra + 3) - 1;
                *(s8*)((char*)extra + 3) = v;
                if (v <= 0)
                {
                    *(s8*)((char*)extra + 2) = 1;
                    *(s16*)extra = 30;
                    Sfx_PlayFromObject((int)obj, SFXthorntail_chew1);
                }
                else
                {
                    Sfx_PlayFromObject((int)obj, SFXthorntail_chew2);
                }
            }
            break;
        }
    case 1:
        {
            int v = ((GameObject*)obj)->anim.alpha - framesThisStep * 16;
            if (v < 0)
            {
                v = 0;
            }
            (*(ObjHitsPriorityState**)&((GameObject*)obj)->anim.hitReactState)->flags &= ~1;
            ((GameObject*)obj)->anim.alpha = v;
            *(s16*)extra = *(s16*)extra - framesThisStep;
            if (*(s16*)extra <= 0)
            {
                GameBit_Set(((DimbarrierPlacement*)def)->unk1E, 1);
                *(s8*)((char*)extra + 2) = 2;
            }
            break;
        }
    }
}

extern u8 Obj_IsLoadingLocked(void);
extern int fn_802972A8(int player);
extern int Obj_AllocObjectSetup(int kind, int id);
extern int Obj_SetupObject(int handle, int a, int b, int c, int d);
extern f32 lbl_803E4864;

/* dimsnowball1c2_update: on a timer, if loading allows and the player is clear,
 * spawn a rolling snowball seeded from the placement params. */
void dimsnowball1c2_update(int* obj);

extern void objMove(int* obj, f32 x, f32 y, f32 z);
extern void ObjHits_SetHitVolumeSlot(int* obj, int a, int b, int c);
extern void ObjHitbox_SetSphereRadius(int* obj, int radius);
extern void spawnExplosion(int* obj, f32 scale, int a, int b, int c, int d, int e, int f, int g);
extern void Obj_FreeObject(int* obj);
extern f32 timeDelta;
extern f32 lbl_803E48A0;
extern f32 lbl_803E48A4;
extern f32 lbl_803E48A8;
extern f32 lbl_803DBEF0;

/* DIMwooddoor_updateFallingDebris: integrate the falling debris under gravity, spin it, and on
 * contact (or scripted trigger) fire the explosion and start the despawn timer. */
void DIMwooddoor_updateFallingDebris(int* obj);

extern int* getTrickyObject(void);
extern void objRenderFn_80041018(int* obj);
extern EffectInterface** gPartfxInterface;
extern f32 lbl_803E4880;
extern f32 lbl_803E4884;
extern f32 lbl_803E4888;

/* dimicewall_update: on shatter, emit two snow particle bursts and latch the
 * gamebit; otherwise let Tricky push through it. */
void dimicewall_update(int* obj);
