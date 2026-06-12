/* DLL 0x01C5 — dimbarrier (Dinosaur Island Mission barrier object). TU: 0x801B1B40–0x801B1D84. */
#include "ghidra_import.h"

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

extern uint GameBit_Get(int eventId);
extern undefined4 GameBit_Set(int eventId, int value);

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

int dimsnowball1c2_getObjectTypeId(void);
int dimbarrier_getExtraSize(void) { return 0x4; }
int dimbarrier_getObjectTypeId(void) { return 0x0; }

extern f32 lbl_803E4860;
extern void objRenderFn_8003b8f4(f32);
extern f32 lbl_803E4898;

void dimbarrier_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0) objRenderFn_8003b8f4(lbl_803E4898);
}

void dimsnowball1c2_init(int obj, u8* p);

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

/* dimsnowball1c2_update: on a timer, if loading allows and the player is clear,
 * spawn a rolling snowball seeded from the placement params. */

/* DIMwooddoor_updateFallingDebris: integrate the falling debris under gravity, spin it, and on
 * contact (or scripted trigger) fire the explosion and start the despawn timer. */

/* dimicewall_update: on shatter, emit two snow particle bursts and latch the
 * gamebit; otherwise let Tricky push through it. */
