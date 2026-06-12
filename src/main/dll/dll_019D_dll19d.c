/* DLL 0x019D — dll19d / torch1CD group. TU: 0x801CBA98–0x801CBD88. */
#pragma scheduling off
#pragma peephole off
#include "main/dll/torch1CD.h"
#include "main/game_object.h"
#include "main/dll/torch1cd_state.h"
#include "main/effect_interfaces.h"



/*
 * --INFO--
 *
 * Function: dll_19B_SeqFn
 * EN v1.0 Address: 0x801CBA98
 * EN v1.0 Size: 636b
 */

/* Trivial 4b 0-arg blr leaves. */

/* 8b "li r3, N; blr" returners. */

/* render-with-objRenderFn_8003b8f4 pattern. */
extern void objRenderFn_8003b8f4(f32);



#pragma scheduling reset
#pragma peephole reset

#include "main/obj_placement.h"
#include "main/effect_interfaces.h"
#include "main/dll_000A_expgfx.h"
#include "main/game_object.h"
#include "main/audio/sfx_ids.h"
#include "main/dll/shrine1CE.h"
#include "main/dll/torch1CD.h"
#include "main/objseq.h"
#include "main/resource.h"



typedef struct Dll19DPlacement
{
    u8 pad0[0x19 - 0x0];
    u8 unk19;
    u8 pad1A[0x20 - 0x1A];
} Dll19DPlacement;


typedef struct Dll19DState
{
    u8 pad0[0x8 - 0x0];
    f32 unk8;
    f32 unkC;
    f32 unk10;
    u8 pad14[0x2C - 0x14];
    s16 unk2C;
    s16 unk2E;
    s16 unk30;
    s16 unk32;
    u16 unk34;
    u8 unk36;
    u8 pad37[0x38 - 0x37];
} Dll19DState;






#pragma peephole off
#pragma scheduling off
extern undefined4 getLActions();


/*
 * --INFO--
 *
 * Function: dll_19B_update
 * EN v1.0 Address: 0x801CBD88
 * EN v1.0 Size: 2124b
 * EN v1.1 Address: 0x801CC33C
 * EN v1.1 Size: 2032b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
extern f32 timeDelta;
extern u8 framesThisStep;



/* Trivial 4b 0-arg blr leaves. */






void dll_19D_render(void)
{
}

void dll_19D_release(void)
{
}

void dll_19D_initialise(void)
{
}

/* 8b "li r3, N; blr" returners. */
int dll_19C_getExtraSize(void);
int dll_19D_getExtraSize(void) { return 0x38; }
int dll_19D_getObjectTypeId(void) { return 0x0; }

/* render-with-objRenderFn_8003b8f4 pattern. */
extern f32 lbl_803E51B0;
#pragma peephole off
#pragma peephole reset

/* Stubs to align function set with v1.0 asm. */
extern void ObjHits_ClearHitVolumes(int obj);
extern void Obj_FreeObject(int obj);
extern void Sfx_PlayFromObject(int obj, int sfx);

#pragma peephole off
#pragma peephole reset

#pragma peephole off
#pragma peephole reset

/*
 * Function: dll_19C_init
 * EN v1.0 Address: 0x801CC950
 * EN v1.0 Size: 64b
 */
#pragma peephole off
#pragma peephole reset

/*
 * Function: dll_19D_free
 * EN v1.0 Address: 0x801CC9A8
 * EN v1.0 Size: 132b
 */
#pragma peephole off
void dll_19D_free(int obj)
{
    register int self = obj;
    register int state = *(int*)&((GameObject*)self)->extra;
    if ((((Dll19DState*)state)->unk36 & 2) == 0)
    {
        getLActions(self, self, 1, 0, 0, 0);
        ((Dll19DState*)state)->unk36 = (u8)((u32)((Dll19DState*)state)->unk36 | 0x2);
    }
    (*gExpgfxInterface)->freeSource2((u32)self);
}
#pragma peephole reset

extern int ObjHits_SetHitVolumeSlot(int obj, int volumeIdx, int hitType, int extra);

/*
 * Function: dll_19D_init
 * EN v1.0 Address: 0x801CCECC
 * EN v1.0 Size: 208b
 */
#pragma peephole off
void dll_19D_init(int obj)
{
    register int self = obj;
    register int state2 = *(int*)&((GameObject*)self)->anim.placementData;
    int slot;

    if ((int)(signed char)*(u8*)(state2 + 0x19) != 0)
    {
        slot = 3;
    }
    else
    {
        slot = 1;
    }
    ObjHits_SetHitVolumeSlot(self, 0xe, slot, 0);

    if ((int)(signed char)((Dll19DPlacement*)state2)->unk19 == 1)
    {
        getLActions(self, self, 0x203, 0, 0, 0);
    }
    else if ((int)(signed char)((Dll19DPlacement*)state2)->unk19 == 2)
    {
        getLActions(self, self, 0x204, 0, 0, 0);
    }
    else
    {
        getLActions(self, self, 0x201, 0, 0, 0);
    }
}
#pragma peephole reset

extern EffectInterface** gPartfxInterface;
extern f32 lbl_803E51B8;

/*
 * Function: dll_19D_hitDetect
 * EN v1.0 Address: 0x801CCA30
 * EN v1.0 Size: 276b
 */
#pragma peephole off
void dll_19D_hitDetect(int obj)
{
    register int self = obj;
    register int state = *(int*)&((GameObject*)self)->extra;
    int state2 = *(int*)&((GameObject*)self)->anim.placementData;
    float vec[6];
    int linkObj;
    void* linkSubObj;

    vec[3] = lbl_803E51B8;
    vec[4] = lbl_803E51B8;
    vec[5] = lbl_803E51B8;
    vec[2] = (float)(int)(s8)((Dll19DPlacement*)state2)->unk19;

    linkObj = *(int*)&((GameObject*)self)->anim.hitReactState;
    linkSubObj = *(void**)&((ObjHitsPriorityState*)linkObj)->lastHitObject;
    if (linkSubObj == 0) return;
    if (*(short*)((u8*)linkSubObj + 0x46) == 0x248) return;

    (*gPartfxInterface)->spawnObject((void*)self, 0x2a0, vec, 1, -1, NULL);
    (*gPartfxInterface)->spawnObject((void*)self, 0x2a0, vec, 1, -1, NULL);
    (*gPartfxInterface)->spawnObject((void*)self, 0x2a0, vec, 1, -1, NULL);
    ((Dll19DState*)state)->unk32 = 0x32;
}
#pragma peephole reset

/*
 * Function: dll_19D_update
 * EN v1.0 Address: 0x801CCB44
 * EN v1.0 Size: 904b
 */
#pragma peephole off
void dll_19D_update(int obj)
{
    register int self = obj;
    register int state = *(int*)(self + 0xb8);
    int def = *(int*)(self + 0x4c);
    int linkObj;
    float vec[6];
    int lifetime;
    s16 timer;
    u32 frames;
    f32 zero;

    vec[3] = lbl_803E51B8;
    vec[4] = lbl_803E51B8;
    vec[5] = lbl_803E51B8;
    vec[2] = (float)(int)(s8) * (u8*)(def + 0x19);

    if ((*(u8*)(state + 0x36) & 1) == 0)
    {
        *(f32*)(state + 0x8) = *(f32*)(self + 0xc);
        *(f32*)(state + 0xc) = *(f32*)(self + 0x10);
        *(f32*)(state + 0x10) = *(f32*)(self + 0x14);
        *(u8*)(state + 0x36) = (u8)((u32) * (u8*)(state + 0x36) | 1);
    }

    linkObj = *(int*)(self + 0x54);
    if (*(s8*)(linkObj + 0xad) != 0)
    {
        Sfx_PlayFromObject(self, SFXsc_mpick1_b);
        (*gPartfxInterface)->spawnObject((void*)self, 0x2a0, vec, 1, -1, NULL);
        (*gPartfxInterface)->spawnObject((void*)self, 0x2a0, vec, 1, -1, NULL);
        (*gPartfxInterface)->spawnObject((void*)self, 0x2a0, vec, 1, -1, NULL);
        *(s16*)(state + 0x32) = 0x32;
    }

    if (*(s16*)(state + 0x32) != 0)
    {
        if ((*(u8*)(state + 0x36) & 2) == 0)
        {
            getLActions(self, self, 1, 0, 0, 0);
            *(u8*)(state + 0x36) = (u8)((u32) * (u8*)(state + 0x36) | 2);
        }
        zero = lbl_803E51B8;
        *(f32*)(self + 0x24) = zero;
        *(f32*)(self + 0x28) = zero;
        *(f32*)(self + 0x2c) = zero;
        ObjHits_ClearHitVolumes(self);
        *(s16*)(state + 0x32) -= 1;
        if (*(s16*)(state + 0x32) <= 0)
        {
            Obj_FreeObject(self);
        }
    }
    else
    {
        *(f32*)(self + 0x80) = *(f32*)(self + 0xc);
        *(f32*)(self + 0x84) = *(f32*)(self + 0x10);
        *(f32*)(self + 0x88) = *(f32*)(self + 0x14);

        *(s16*)(self + 0x0) = (s16)(*(s16*)(self + 0x0) + *(s16*)(state + 0x2e) * (u16)framesThisStep);
        *(s16*)(self + 0x4) = (s16)(*(s16*)(self + 0x4) + *(s16*)(state + 0x2c) * (u16)framesThisStep);
        (*gPartfxInterface)->spawnObject((void*)self, 0x29d, vec, 4, -1, NULL);

        if ((*(s16*)(state + 0x30) -= framesThisStep) <= 0)
        {
            (*gPartfxInterface)->spawnObject((void*)self, 0x29e, vec, 4, -1, NULL);
            (*gPartfxInterface)->spawnObject((void*)self, 0x29f, vec, 4, -1, NULL);
            (*gPartfxInterface)->spawnObject((void*)self, 0x2a1, vec, 4, -1, NULL);
            *(s16*)(state + 0x30) = 0x32;
        }

        *(f32*)(state + 0x8) = *(f32*)(self + 0x24) * timeDelta + *(f32*)(state + 0x8);
        *(f32*)(state + 0xc) = *(f32*)(self + 0x28) * timeDelta + *(f32*)(state + 0xc);
        *(f32*)(state + 0x10) = *(f32*)(self + 0x2c) * timeDelta + *(f32*)(state + 0x10);
        *(u16*)(state + 0x34) = *(u16*)(state + 0x34) + (u16)framesThisStep * 0x5dc;
        *(f32*)(self + 0xc) = *(f32*)(state + 0x8);
        *(f32*)(self + 0x10) = *(f32*)(state + 0xc);
        *(f32*)(self + 0x14) = *(f32*)(state + 0x10);

        frames = framesThisStep;
        lifetime = *(int*)(self + 0xf4);
        *(int*)(self + 0xf4) = lifetime - frames;
        if ((int)(lifetime - frames) < 0)
        {
            Obj_FreeObject(self);
        }
    }
}
#pragma peephole reset
