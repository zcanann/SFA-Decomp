/* DLL 0x019D — dll19d / torch1CD group. TU: 0x801CBA98–0x801CBD88. */
#include "main/dll/torch1CD.h"
#include "main/dll_000A_expgfx.h"
#include "main/game_object.h"
#include "main/audio/sfx_ids.h"
#include "main/dll/torch1CD.h"
#include "main/objhits.h"
#include "main/dll/VF/vf_shared.h"

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

extern u32 getLActions();
extern f32 timeDelta;
extern u8 framesThisStep;
extern f32 lbl_803E51B0;
extern void Sfx_PlayFromObject(u32 obj, u16 sfxId);
extern f32 lbl_803E51B8;

void dll_19D_render(void)
{
}

void dll_19D_release(void)
{
}

void dll_19D_initialise(void)
{
}

int dll_19D_getExtraSize(void) { return 0x38; }
int dll_19D_getObjectTypeId(void) { return 0x0; }

/*
 * Function: dll_19C_init
 * EN v1.0 Address: 0x801CC950
 * EN v1.0 Size: 64b
 */

/*
 * Function: dll_19D_free
 * EN v1.0 Address: 0x801CC9A8
 * EN v1.0 Size: 132b
 */
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

/*
 * Function: dll_19D_init
 * EN v1.0 Address: 0x801CCECC
 * EN v1.0 Size: 208b
 */
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

/*
 * Function: dll_19D_hitDetect
 * EN v1.0 Address: 0x801CCA30
 * EN v1.0 Size: 276b
 */
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

/*
 * Function: dll_19D_update
 * EN v1.0 Address: 0x801CCB44
 * EN v1.0 Size: 904b
 */
void dll_19D_update(int obj)
{
    register int self = obj;
    register int state = *(int*)&((GameObject*)self)->extra;
    int def = *(int*)&((GameObject*)self)->anim.placementData;
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

    if ((((Dll19DState*)state)->unk36 & 1) == 0)
    {
        ((Dll19DState*)state)->unk8 = ((GameObject*)self)->anim.localPosX;
        ((Dll19DState*)state)->unkC = ((GameObject*)self)->anim.localPosY;
        ((Dll19DState*)state)->unk10 = ((GameObject*)self)->anim.localPosZ;
        ((Dll19DState*)state)->unk36 = (u8)((u32)((Dll19DState*)state)->unk36 | 1);
    }

    linkObj = *(int*)&((GameObject*)self)->anim.hitReactState;
    if (*(s8*)(linkObj + 0xad) != 0)
    {
        Sfx_PlayFromObject(self, SFXsc_mpick1_b);
        (*gPartfxInterface)->spawnObject((void*)self, 0x2a0, vec, 1, -1, NULL);
        (*gPartfxInterface)->spawnObject((void*)self, 0x2a0, vec, 1, -1, NULL);
        (*gPartfxInterface)->spawnObject((void*)self, 0x2a0, vec, 1, -1, NULL);
        ((Dll19DState*)state)->unk32 = 0x32;
    }

    if (((Dll19DState*)state)->unk32 != 0)
    {
        if ((((Dll19DState*)state)->unk36 & 2) == 0)
        {
            getLActions(self, self, 1, 0, 0, 0);
            ((Dll19DState*)state)->unk36 = (u8)((u32)((Dll19DState*)state)->unk36 | 2);
        }
        zero = lbl_803E51B8;
        ((GameObject*)self)->anim.velocityX = zero;
        ((GameObject*)self)->anim.velocityY = zero;
        ((GameObject*)self)->anim.velocityZ = zero;
        ObjHits_ClearHitVolumes(self);
        ((Dll19DState*)state)->unk32 -= 1;
        if (((Dll19DState*)state)->unk32 <= 0)
        {
            Obj_FreeObject(self);
        }
    }
    else
    {
        ((GameObject*)self)->anim.previousLocalPosX = ((GameObject*)self)->anim.localPosX;
        ((GameObject*)self)->anim.previousLocalPosY = ((GameObject*)self)->anim.localPosY;
        ((GameObject*)self)->anim.previousLocalPosZ = ((GameObject*)self)->anim.localPosZ;

        ((GameObject*)self)->anim.rotX = (s16)(((GameObject*)self)->anim.rotX + ((Dll19DState*)state)->unk2E * framesThisStep);
        ((GameObject*)self)->anim.rotZ = (s16)(((GameObject*)self)->anim.rotZ + ((Dll19DState*)state)->unk2C * framesThisStep);
        (*gPartfxInterface)->spawnObject((void*)self, 0x29d, vec, 4, -1, NULL);

        if ((((Dll19DState*)state)->unk30 -= framesThisStep) <= 0)
        {
            (*gPartfxInterface)->spawnObject((void*)self, 0x29e, vec, 4, -1, NULL);
            (*gPartfxInterface)->spawnObject((void*)self, 0x29f, vec, 4, -1, NULL);
            (*gPartfxInterface)->spawnObject((void*)self, 0x2a1, vec, 4, -1, NULL);
            ((Dll19DState*)state)->unk30 = 0x32;
        }

        ((Dll19DState*)state)->unk8 = ((GameObject*)self)->anim.velocityX * timeDelta + ((Dll19DState*)state)->unk8;
        ((Dll19DState*)state)->unkC = ((GameObject*)self)->anim.velocityY * timeDelta + ((Dll19DState*)state)->unkC;
        ((Dll19DState*)state)->unk10 = ((GameObject*)self)->anim.velocityZ * timeDelta + ((Dll19DState*)state)->unk10;
        ((Dll19DState*)state)->unk34 = ((Dll19DState*)state)->unk34 + framesThisStep * 0x5dc;
        ((GameObject*)self)->anim.localPosX = ((Dll19DState*)state)->unk8;
        ((GameObject*)self)->anim.localPosY = ((Dll19DState*)state)->unkC;
        ((GameObject*)self)->anim.localPosZ = ((Dll19DState*)state)->unk10;

        frames = framesThisStep;
        lifetime = *(int*)(self + 0xf4);
        *(int*)(self + 0xf4) = lifetime - frames;
        if ((int)(lifetime - frames) < 0)
        {
            Obj_FreeObject(self);
        }
    }
}
