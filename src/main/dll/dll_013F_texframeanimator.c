/* DLL 0x13F - TexFrameAnimator [801948C0-80195008) */
#include "main/effect_interfaces.h"
#include "main/game_object.h"







extern uint GameBit_Get(int eventId);
extern undefined4 GameBit_Set(int eventId, int value);
extern undefined8 ObjGroup_RemoveObject();


/*
 * --INFO--
 *
 * Function: wallanimator_setScale
 * EN v1.0 Address: 0x8019443C
 * EN v1.0 Size: 264b
 * EN v1.1 Address: 0x80194688
 * EN v1.1 Size: 332b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */

/*
 * --INFO--
 *
 * Function: FUN_80194544
 * EN v1.0 Address: 0x80194544
 * EN v1.0 Size: 184b
 * EN v1.1 Address: 0x801947D4
 * EN v1.1 Size: 208b
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
 * Function: objFn_801948c0
 * EN v1.0 Address: 0x801948C0
 * EN v1.0 Size: 164b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
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
 * Function: FUN_80194a70
 * EN v1.0 Address: 0x80194A70
 * EN v1.0 Size: 160b
 * EN v1.1 Address: 0x80194E3C
 * EN v1.1 Size: 164b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */

/*
 * --INFO--
 *
 * Function: FUN_80194b10
 * EN v1.0 Address: 0x80194B10
 * EN v1.0 Size: 512b
 * EN v1.1 Address: 0x80194EE0
 * EN v1.1 Size: 504b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling on
#pragma peephole on





#pragma scheduling off
#pragma peephole off


/*
 * --INFO--
 *
 * Function: wallanimator_getExtraSize
 * EN v1.0 Address: 0x8019469C
 * EN v1.0 Size: 8b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */

/*
 * --INFO--
 *
 * Function: xyzanimator_getExtraSize
 * EN v1.0 Address: 0x80194B5C
 * EN v1.0 Size: 8b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */


/* render-with-objRenderFn_8003b8f4 pattern. */
extern void objRenderFn_8003b8f4(f32);






/* segment pragma-stack balance (re-split): */
#pragma scheduling reset
#pragma scheduling reset
#pragma scheduling reset
#pragma scheduling reset
#pragma peephole reset
#pragma peephole reset
#pragma peephole reset
#pragma peephole reset

#include "main/map_block.h"
#include "main/dll/MMP/MMP_asteroid.h"
#include "main/obj_placement.h"
#include "main/effect_interfaces.h"
#include "main/dll_000A_expgfx.h"
#include "main/dll/path_control_interface.h"
#include "main/game_object.h"

typedef struct TexframeanimatorPlacement
{
    u8 pad0[0x18 - 0x0];
    s16 unk18;
    s16 unk1A;
    s16 unk1C;
    s16 unk1E;
    s16 unk20;
    s16 unk22;
    s16 unk24;
    u8 pad26[0x3C - 0x26];
    u8 unk3C;
    u8 pad3D[0x3E - 0x3D];
    s16 unk3E;
} TexframeanimatorPlacement;












/*
 * --INFO--
 *
 * Function: xyzanimator_update
 * EN v1.0 Address: 0x80195008
 * EN v1.0 Size: 164b
 * EN v1.1 Address: 0x801950E0
 * EN v1.1 Size: 172b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */


/*
 * --INFO--
 *
 * Function: FUN_801950ac
 * EN v1.0 Address: 0x801950AC
 * EN v1.0 Size: 40b
 * EN v1.1 Address: 0x8019518C
 * EN v1.1 Size: 48b
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
 * Function: FUN_801954f0
 * EN v1.0 Address: 0x801954F0
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80195584
 * EN v1.1 Size: 4624b
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
 * Function: FUN_801954f4
 * EN v1.0 Address: 0x801954F4
 * EN v1.0 Size: 176b
 * EN v1.1 Address: 0x80196794
 * EN v1.1 Size: 192b
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
 * Function: FUN_80195b40
 * EN v1.0 Address: 0x80195B40
 * EN v1.0 Size: 52b
 * EN v1.1 Address: 0x80196EA8
 * EN v1.1 Size: 48b
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
 * Function: FUN_80195b74
 * EN v1.0 Address: 0x80195B74
 * EN v1.0 Size: 40b
 * EN v1.1 Address: 0x80196ED8
 * EN v1.1 Size: 52b
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









void texframeanimator_free(void)
{
}

void texframeanimator_hitDetect(void)
{
}

void texframeanimator_release(void)
{
}

void texframeanimator_initialise(void)
{
}

void fogcontrol_hitDetect(void);

typedef struct TexFrameAnimatorState
{
    int textureSlot;
    u8 speed;
    u8 pad5[3];
    int endFrame;
    int wrapFrame;
    int frame;
    u8 flag80 : 1;
    u8 done : 1;
    u8 active : 1;
    u8 flagLow : 5;
} TexFrameAnimatorState;

extern u8 framesThisStep;
extern char sTexFrameAnimDebugFormat[];
extern int* return0_80056694(int* block, int textureSlot);
extern int* mapTextureOverrideGetEntry(int idx);
extern void fn_80137948(char* fmt, ...);

void texframeanimator_update(int* obj)
{
    extern int* mapGetBlock(int idx); /* #57 */
    extern int objPosToMapBlockIdx(f32 x, f32 y, f32 z); /* #57 */
    TexFrameAnimatorState* state;
    u8* params;
    int* block;
    int* textureHit;
    int* textureEntry;

    state = ((GameObject*)obj)->extra;
    params = *(u8**)&((GameObject*)obj)->anim.placementData;

    if ((state->active == 0) &&
        ((u32)GameBit_Get(((TexframeanimatorPlacement*)params)->unk20) != 0) &&
        (state->done == 0))
    {
        state->active = 1;
        state->frame = 0;
    }

    if ((state->active != 0) && (state->textureSlot != 0))
    {
        block = mapGetBlock(objPosToMapBlockIdx(((GameObject*)obj)->anim.localPosX,
                                                ((GameObject*)obj)->anim.localPosY,
                                                ((GameObject*)obj)->anim.localPosZ));
        if ((block != NULL) && ((((MapBlockData*)block)->unk4 & 8) != 0))
        {
            textureHit = return0_80056694(block, state->textureSlot);
            if (textureHit != NULL)
            {
                textureEntry = mapTextureOverrideGetEntry(*(s16*)textureHit);
                state->frame += state->speed * framesThisStep;
                fn_80137948(sTexFrameAnimDebugFormat, state->frame);
                if (state->frame < 0)
                {
                    state->frame = 0;
                }
                else if (state->frame > state->endFrame)
                {
                    if (((TexframeanimatorPlacement*)params)->unk1E != -1)
                    {
                        GameBit_Set(((TexframeanimatorPlacement*)params)->unk1E, 1);
                        state->active = 0;
                        state->done = 1;
                        state->frame = state->endFrame;
                    }
                    else
                    {
                        state->frame = state->wrapFrame;
                    }
                }
                textureEntry[1] = state->frame;
            }
        }
    }
}

void texframeanimator_init(int* obj, u8* params)
{
    TexFrameAnimatorState* state;
    u8 done;

    state = ((GameObject*)obj)->extra;
    state->textureSlot = (s8)params[0x19];
    state->endFrame = *(s16*)(params + 0x1a) << 8;
    state->speed = (u8) * (s16*)(params + 0x1c);
    state->wrapFrame = (s8)params[0x18] << 8;
    done = (u8)GameBit_Get(*(s16*)(params + 0x1e));
    if ((state->done = done) != 0)
    {
        state->frame = state->endFrame;
        state->active = 1;
    }
    ((GameObject*)obj)->objectFlags = (u16)(((GameObject*)obj)->objectFlags | 0x2000);
    ((GameObject*)obj)->objectFlags = (u16)(((GameObject*)obj)->objectFlags | 0x4000);
}

/* 8b "li r3, N; blr" returners. */
int explodeanimator_getExtraSize(void);
int texframeanimator_getExtraSize(void) { return 0x18; }
int texframeanimator_getObjectTypeId(void) { return 0x0; }
int fogcontrol_getExtraSize(void);

/* render-with-objRenderFn_8003b8f4 pattern. */
extern f32 lbl_803E4060;


void texframeanimator_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0) objRenderFn_8003b8f4(lbl_803E4060);
}

/* ObjGroup_RemoveObject(x, N) wrappers. */
void explodeanimator_free(int x);

/* state encode: ((obj->_X)->_Y << shift) | const. */

/* Drift-recovery: add new fns with v1.0 names. */












/* EN v1.0 0x80196990  size: 1752b  dimbossicesmash_update: gate on the
 * trigger gamebit, integrate velocity/rotation with per-axis gravity
 * clamps, run the path-control hooks with surface bounce, fade alpha over
 * the lifetime window, and emit the two trail particles. */


/* EN v1.0 0x80196520  size: 1008b  fn_80196520: seed the icesmash launch
 * state from the setup record: spawn position/rotation, launch velocity
 * (optionally homing on the target point), rotation velocities and the
 * gravity/clamp direction flags. */

/* EN v1.0 0x80197068  size: 284b  dimbossicesmash_init. */


/* EN v1.0 0x80197474  size: 648b  fogcontrol_update: ramp the fog blend
 * toward the gamebit-selected target and feed the heavy fog params. */
