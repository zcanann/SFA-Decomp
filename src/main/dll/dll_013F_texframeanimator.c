/* DLL 0x13F - TexFrameAnimator [801948C0-80195008) */
#include "main/game_object.h"
#include "main/map_block.h"
#include "main/gamebits.h"
#include "main/dll/VF/vf_shared.h"

#define TEXFRAMEANIMATOR_OBJFLAG_HIDDEN 0x4000
#define TEXFRAMEANIMATOR_OBJFLAG_HITDETECT_DISABLED 0x2000

typedef struct TexframeanimatorPlacement
{
    u8 pad0[0x18 - 0x0];
    s8 wrapFrame;    /* 0x18 */
    s8 textureSlot;  /* 0x19 */
    s16 endFrame;    /* 0x1A */
    s16 speed;       /* 0x1C */
    s16 completedGameBit;
    s16 triggerGameBit;
    s16 unk22;
    s16 unk24;
    u8 pad26[0x3C - 0x26];
    u8 unk3C;
    u8 pad3D[0x3E - 0x3D];
    s16 unk3E;
} TexframeanimatorPlacement;

char sTexFrameAnimDebugFormat[] = " TEXFRAMEANIM %i ";
extern int* return0_80056694(int* block, int textureSlot);
extern int* mapTextureOverrideGetEntry(int idx);
extern void fn_80137948(char* fmt, ...);
extern f32 lbl_803E4060;

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

void texframeanimator_update(int* obj)
{
    extern void* mapGetBlock(int i); /* #57 */
    extern int objPosToMapBlockIdx(f32 x, f32 y, f32 z); /* #57 */
    TexFrameAnimatorState* state;
    u8* params;
    int* block;
    int* textureHit;
    int* textureEntry;

    state = ((GameObject*)obj)->extra;
    params = *(u8**)&((GameObject*)obj)->anim.placementData;

    if ((state->active == 0) &&
        ((u32)GameBit_Get(((TexframeanimatorPlacement*)params)->triggerGameBit) != 0) &&
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
        if (block == NULL || !(((MapBlockData*)block)->flags4 & 8))
        {
            return;
        }
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
                if (((TexframeanimatorPlacement*)params)->completedGameBit != -1)
                {
                    GameBit_Set(((TexframeanimatorPlacement*)params)->completedGameBit, 1);
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

void texframeanimator_init(int* obj, u8* params)
{
    TexFrameAnimatorState* state;
    u8 done;

    state = ((GameObject*)obj)->extra;
    state->textureSlot = ((TexframeanimatorPlacement*)params)->textureSlot;
    state->endFrame = ((TexframeanimatorPlacement*)params)->endFrame << 8;
    state->speed = (u8)((TexframeanimatorPlacement*)params)->speed;
    state->wrapFrame = ((TexframeanimatorPlacement*)params)->wrapFrame << 8;
    done = GameBit_Get(((TexframeanimatorPlacement*)params)->completedGameBit);
    if ((state->done = done) != 0)
    {
        state->frame = state->endFrame;
        state->active = 1;
    }
    ((GameObject*)obj)->objectFlags = (u16)(((GameObject*)obj)->objectFlags | TEXFRAMEANIMATOR_OBJFLAG_HITDETECT_DISABLED);
    ((GameObject*)obj)->objectFlags = (u16)(((GameObject*)obj)->objectFlags | TEXFRAMEANIMATOR_OBJFLAG_HIDDEN);
}

int texframeanimator_getExtraSize(void) { return 0x18; }
int texframeanimator_getObjectTypeId(void) { return 0x0; }

void texframeanimator_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0) objRenderFn_8003b8f4(lbl_803E4060);
}


/* EN v1.0 0x80197068  size: 284b  dimbossicesmash_init. */

/* descriptor/ptr table auto 0x80322400-0x803224e0 */
extern u8 WaterFallSpray_free[];
extern u8 WaterFallSpray_getExtraSize[];
extern u8 WaterFallSpray_init[];
extern u8 WaterFallSpray_render[];
extern u8 WaterFallSpray_update[];
extern u8 fogcontrol_free[];
extern u8 fogcontrol_getExtraSize[];
extern u8 fogcontrol_getObjectTypeId[];
extern u8 fogcontrol_hitDetect[];
extern u8 fogcontrol_init[];
extern u8 fogcontrol_update[];
extern u8 lightning_free[];
extern u8 lightning_getExtraSize[];
extern u8 lightning_init[];
extern u8 lightning_render[];
extern u8 lightning_update[];
extern u8 sfxplayerObj_free[];
extern u8 sfxplayerObj_getExtraSize[];
extern u8 sfxplayerObj_init[];
extern u8 sfxplayerObj_update[];

u32 gFogControlObjDescriptor[14] = { 0x00000000, 0x00000000, 0x00000000, 0x00090000, 0x00000000, 0x00000000, 0x00000000, (u32)fogcontrol_init, (u32)fogcontrol_update, (u32)fogcontrol_hitDetect, 0x00000000, (u32)fogcontrol_free, (u32)fogcontrol_getObjectTypeId, (u32)fogcontrol_getExtraSize };
u32 gLightningObjDescriptor[14] = { 0x00000000, 0x00000000, 0x00000000, 0x00090000, 0x00000000, 0x00000000, 0x00000000, (u32)lightning_init, (u32)lightning_update, 0x00000000, (u32)lightning_render, (u32)lightning_free, 0x00000000, (u32)lightning_getExtraSize };
u32 gWaterFallSprayObjDescriptor[14] = { 0x00000000, 0x00000000, 0x00000000, 0x00090000, 0x00000000, 0x00000000, 0x00000000, (u32)WaterFallSpray_init, (u32)WaterFallSpray_update, 0x00000000, (u32)WaterFallSpray_render, (u32)WaterFallSpray_free, 0x00000000, (u32)WaterFallSpray_getExtraSize };
u32 gSfxPlayerObjDescriptor[14] = { 0x00000000, 0x00000000, 0x00000000, 0x00090000, 0x00000000, 0x00000000, 0x00000000, (u32)sfxplayerObj_init, (u32)sfxplayerObj_update, 0x00000000, 0x00000000, (u32)sfxplayerObj_free, 0x00000000, (u32)sfxplayerObj_getExtraSize };
