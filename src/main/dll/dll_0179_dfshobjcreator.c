/* === moved from main/dll/dll_19C.c [801C3B68-801C3BB0) (TU re-split, docs/boundary_audit.md) === */
#include "main/obj_placement.h"
#include "main/objseq.h"
#include "main/screen_transition.h"




extern void objRenderFn_8003b8f4(f32 scale);
extern f32 timeDelta;
extern void Sfx_PlayFromObject(int obj, int sfxId);


typedef struct DfshShrinePlacement
{
    ObjPlacement base;
    s8 initialYaw;
    u8 pad19;
    s16 startDelay;
    u8 pad1C[0x24 - 0x1C];
} DfshShrinePlacement;

STATIC_ASSERT(sizeof(DfshShrinePlacement) == 0x24);
STATIC_ASSERT(offsetof(DfshShrinePlacement, initialYaw) == 0x18);
STATIC_ASSERT(offsetof(DfshShrinePlacement, startDelay) == 0x1A);

/*
 * --INFO--
 *
 * Function: dfsh_shrine_render
 * EN v1.0 Address: 0x801C2E68
 * EN v1.0 Size: 184b
 * EN v1.1 Address: 0x801C2EC8
 * EN v1.1 Size: 852b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */




/*
 * --INFO--
 *
 * Function: FUN_801c3134
 * EN v1.0 Address: 0x801C3134
 * EN v1.0 Size: 340b
 * EN v1.1 Address: 0x801C321C
 * EN v1.1 Size: 364b
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
 * Function: FUN_801c3a9c
 * EN v1.0 Address: 0x801C3A9C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801C3ABC
 * EN v1.1 Size: 288b
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
 * Function: FUN_801c3aa0
 * EN v1.0 Address: 0x801C3AA0
 * EN v1.0 Size: 96b
 * EN v1.1 Address: 0x801C3BDC
 * EN v1.1 Size: 92b
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














void dfsh_objcreator_free(void)
{
}

void dfsh_objcreator_hitDetect(void)
{
}

/* 8b "li r3, N; blr" returners. */
int SpiritPrize_getExtraSize(void);
int dfsh_objcreator_getExtraSize(void) { return 0x4; }
int dfsh_objcreator_getObjectTypeId(void) { return 0x0; }

/* render-with-objRenderFn_8003b8f4 pattern. */
extern f32 lbl_803E4EB8;

void dfsh_objcreator_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0) objRenderFn_8003b8f4(lbl_803E4EB8);
}

void SpiritPrize_render(int* obj, int p2, int p3, int p4, int p5, s8 visible);


/* segment pragma-stack balance (re-split): */
#pragma scheduling reset
#pragma scheduling reset
#pragma scheduling reset
#pragma scheduling reset
#pragma peephole reset
#pragma peephole reset
#pragma peephole reset
#pragma peephole reset

#include "main/audio/sfx_ids.h"
#include "main/obj_placement.h"
#include "main/effect_interfaces.h"
#include "main/game_object.h"
#include "main/resource.h"


extern u8 Obj_IsLoadingLocked(void);
extern void* Obj_AllocObjectSetup(int size, int objectId);
extern void* Obj_SetupObject(void* setup, int mode, int mapLayer, int objIndex, int parent);


typedef struct DfshObjCreatorState
{
    s16 spawnTimer;
    s16 spawnTimerStep;
} DfshObjCreatorState;

/*
 * --INFO--
 *
 * Function: dfsh_objcreator_update
 * EN v1.0 Address: 0x801C3BB0
 * EN v1.0 Size: 740b
 * EN v1.1 Address: 0x801C3CC4
 * EN v1.1 Size: 612b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void dfsh_objcreator_update(int obj)
{
    extern uint GameBit_Get(int eventId);
    u8* setup = *(u8**)&((GameObject*)obj)->anim.placementData;
    DfshObjCreatorState* state = ((GameObject*)obj)->extra;
    void* resource;
    u8* spawnSetup;

    if (GameBit_Get(0x589) != 0)
    {
        ((GameObject*)obj)->unkF8 = 0;
        return;
    }

    if (((GameObject*)obj)->unkF8 == 0 && GameBit_Get((s8)setup[0x1f] + 0xf6) != 0)
    {
        resource = Resource_Acquire(0x82, 1);
        (*(void (**)(int, int, int, int, int, int))(*(int*)resource + 4))(
            obj, 0, 0, 1, -1, 0);
        (*(void (**)(int, int, int, int, int, int))(*(int*)resource + 4))(
            obj, 1, 0, 1, -1, 0);
        Sfx_PlayFromObject(obj, SFXsc_gemrun1022);
        Resource_Release(resource);
        state->spawnTimerStep = 1;
        ((GameObject*)obj)->unkF8 = 1;
    }

    if (state->spawnTimerStep != 0)
    {
        state->spawnTimer =
            (s16)(state->spawnTimer - state->spawnTimerStep * (int)timeDelta);
    }

    if (Obj_IsLoadingLocked() != 0 && state->spawnTimer <= 0)
    {
        spawnSetup = Obj_AllocObjectSetup(0x38, 0x11);
        *(f32*)(spawnSetup + 0x08) = ((ObjPlacement*)setup)->posX;
        *(f32*)(spawnSetup + 0x0c) = ((ObjPlacement*)setup)->posY;
        *(f32*)(spawnSetup + 0x10) = ((ObjPlacement*)setup)->posZ;
        *(int*)(spawnSetup + 0x14) = ((ObjPlacement*)setup)->mapId;
        spawnSetup[0x04] = setup[0x04];
        spawnSetup[0x05] = setup[0x05];
        spawnSetup[0x06] = setup[0x06];
        spawnSetup[0x07] = setup[0x07];
        spawnSetup[0x27] = 3;
        *(s16*)(spawnSetup + 0x18) = 0x1e7;
        *(s16*)(spawnSetup + 0x30) = -1;
        *(s16*)(spawnSetup + 0x1a) = -1;
        *(s16*)(spawnSetup + 0x1c) = -1;
        *(s8*)(spawnSetup + 0x2a) = (s8)(*(s16*)obj >> 8);
        spawnSetup[0x2b] = 2;
        if (GameBit_Get(0xfc) != 0)
        {
            *(s16*)(spawnSetup + 0x22) = 0x49;
        }
        else
        {
            *(s16*)(spawnSetup + 0x22) = -1;
        }
        spawnSetup[0x29] = 0xff;
        *(s8*)(spawnSetup + 0x2e) = -1;
        *(u16*)(spawnSetup + 0x34) = 0xffff;
        Obj_SetupObject(spawnSetup, 5, ((GameObject*)obj)->anim.mapEventSlot, -1,
                        *(int*)&((GameObject*)obj)->anim.parent);
        state->spawnTimer = 100;
        state->spawnTimerStep = 0;
    }
}

/*
 * --INFO--
 *
 * Function: DFSH_LaserBeam_init
 * EN v1.0 Address: 0x801C3E94
 * EN v1.0 Size: 516b
 * EN v1.1 Address: 0x801C3F28
 * EN v1.1 Size: 520b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
extern ModgfxInterface** gModgfxInterface;


/*
 * --INFO--
 *
 * Function: FUN_801c4098
 * EN v1.0 Address: 0x801C4098
 * EN v1.0 Size: 40b
 * EN v1.1 Address: 0x801C4130
 * EN v1.1 Size: 52b
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
 * Function: dfsh_objcreator_release
 * EN v1.0 Address: 0x801C3E34
 * EN v1.0 Size: 4b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off
void dfsh_objcreator_release(void)
{
}

/*
 * --INFO--
 *
 * Function: dfsh_objcreator_initialise
 * EN v1.0 Address: 0x801C3E38
 * EN v1.0 Size: 4b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void dfsh_objcreator_initialise(void)
{
}

void dfsh_objcreator_init(int obj, s8* def)
{
    DfshObjCreatorState* state = ((GameObject*)obj)->extra;
    *(s16*)obj = (s16)((s32)def[0x1E] << 8);
    ((GameObject*)obj)->unkF8 = 0;
    state->spawnTimer = 100;
    state->spawnTimerStep = 0;
    *(u8*)((char*)obj + 0x37) = 0xFF;
    ((GameObject*)obj)->anim.alpha = 0xFF;
}

/* Trivial 4b 0-arg blr leaves. */


/* 8b "li r3, N; blr" returners. */
