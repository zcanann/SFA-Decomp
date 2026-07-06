/*
 * dimlavasmash (DLL 0x1C7) - DIM lava-smash hazard; a surface object that
 * rises and smashes when struck by a certain hit type, sets surface-passable
 * flags on the underlying map block, and triggers a game-bit sequence event
 * on completion.
 */
#include "main/dll/DIM/dimcannon_state.h"
#include "main/game_object.h"
#include "main/audio/sfx_ids.h"
#include "main/dll/DIM/DIMlevcontrol.h"
#include "main/objseq.h"
#include "main/gamebits.h"
#include "main/dll/VF/vf_shared.h"
#include "main/objhits.h"
#include "main/audio/sfx.h"

#define DIMLAVASMASH_OBJFLAG_HITDETECT_DISABLED 0x2000


extern f32 lbl_803E48F8;
STATIC_ASSERT(sizeof(DimCannonState) == 0xb4);


extern int objPosToMapBlockIdx(f32 x, f32 y, f32 z);
extern int mapBlockFn_800606ec(int arg1, int idx);
extern int mapBlockFn_80060678(void);
extern int fn_8006070C(int arg1, int idx);
extern int Shader_getLayer(int layer, int idx);

void dimlavasmash_free(void)
{
}

void dimlavasmash_hitDetect(void)
{
}

void dimlavasmash_render(int* obj, int p2, int p3, int p4, int p5, s8 visible)
{
    u8* state = ((GameObject*)obj)->extra;
    if (state[2] == 2 && visible != 0)
    {
        ((void (*)(int*, int, int, int, int, f32))objRenderModelAndHitVolumes)(obj, p2, p3, p4, p5, lbl_803E48F8);
    }
}

void dimlavasmash_update(int* obj)
{
    u8* state;
    ObjHitsPriorityState* hitState;
    state = ((GameObject*)obj)->extra;
    if (state[2] == 1)
    {
        hitState = (ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState;
        hitState->flags &= ~1;
    }
    else if (((GameObject*)obj)->unkF4 == 0)
    {
        if ((s8)state[0] != -1)
        {
            (*gObjectTriggerInterface)->runSequence((s8)state[0], obj, -1);
        }
        ((GameObject*)obj)->unkF4 = 1;
    }
}

int dimlavasmash_getExtraSize(void) { return 0x3; }
int dimlavasmash_getObjectTypeId(void) { return 0x0; }

typedef struct DimlavasmashPlacement
{
    u8 pad0[0x1E - 0x0];
    s16 triggerGameBit;
    s16 gateGameBit;
    u8 pad22[0x28 - 0x22];
} DimlavasmashPlacement;

typedef struct DimlavasmashState
{
    s8 unk0; /* 0x0 init source: def.unk1C */
    u8 surfaceLayerId; /* surface material/layer index passed to setBlockSurfaceFlags */
    u8 state;
    u8 pad3[0x7 - 0x3];
    u8 unk7;
    u8 pad8[0x9 - 0x8];
    s8 unk9;
    s8 unkA;
    s8 unkB;
    u8 padC[0x10 - 0xC];
} DimlavasmashState;

#pragma dont_inline on
#pragma opt_propagation off
void dimlavasmash_setBlockSurfaceFlags(int arg1, int arg2, int arg3)
{
    int clearMask;
    int i;
    int j;
    int* block;
    int got;
    for (j = 0; j < (int)*(u16*)((char*)arg1 + 0x9a); j++)
    {
        block = (int*)mapBlockFn_800606ec(arg1, j);
        got = mapBlockFn_80060678();
        if (arg3 == got)
        {
            if (arg2 != 0)
            {
                *(u32*)(block + 0x10 / 4) &= ~2LL;
                *(u32*)(block + 0x10 / 4) &= ~1LL;
            }
            else
            {
                block[0x10 / 4] = block[0x10 / 4] | 2;
                block[0x10 / 4] = block[0x10 / 4] | 1;
            }
        }
    }
    for (i = 0, clearMask = ~2; i < (int)*(u8*)((char*)arg1 + 0xa2); i++)
    {
        block = (int*)fn_8006070C(arg1, i);
        if (arg3 == (int)*(u8*)((char*)Shader_getLayer((int)block, 0) + 5))
        {
            if (arg2 != 0)
            {
                *(u32*)(block + 0x3c / 4) &= clearMask;
            }
            else
            {
                block[0x3c / 4] = block[0x3c / 4] | 2;
            }
        }
    }
}
#pragma opt_propagation reset
#pragma dont_inline reset

#define DIMLAVASMASH_HIT_SEQID_CANNONBALL 397  /* dimlavaball cannonball (0x18d) */

int dimlavasmash_SeqFn(int obj, int unused, ObjAnimUpdateState* animUpdate)
{
    extern int mapGetBlock(void);
    int* def;
    int hit;
    int block;
    int* state;
    ObjHitsPriorityState* hitState;
    state = ((GameObject*)obj)->extra;
    def = *(int**)&((GameObject*)obj)->anim.placementData;
    if (((DimlavasmashState*)state)->state == 0)
    {
        if (GameBit_Get(((DimlavasmashPlacement*)def)->gateGameBit) != 0)
        {
            hitState = (ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState;
            hitState->flags |= 1;
            if (ObjHits_GetPriorityHit(obj, &hit, 0, 0) != 0)
            {
                if (((GameObject*)hit)->anim.seqId == DIMLAVASMASH_HIT_SEQID_CANNONBALL)
                {
                    ((DimlavasmashState*)state)->state = 2;
                    Sfx_PlayFromObject(obj, SFXbaddie_eggsnatch_sniff1);
                    objPosToMapBlockIdx(((GameObject*)obj)->anim.localPosX,
                                        ((GameObject*)obj)->anim.localPosY,
                                        ((GameObject*)obj)->anim.localPosZ);
                    block = mapGetBlock();
                    if ((void*)block != NULL)
                    {
                        dimlavasmash_setBlockSurfaceFlags(block, 1, ((DimlavasmashState*)state)->surfaceLayerId);
                        dimlavasmash_setBlockSurfaceFlags(block, 0, ((DimlavasmashState*)state)->surfaceLayerId + 1);
                    }
                }
            }
        }
    }
    else
    {
        if (animUpdate->triggerCommand == 1)
        {
            GameBit_Set(((DimlavasmashPlacement*)def)->triggerGameBit, 1);
            ((DimlavasmashState*)state)->state = 1;
        }
    }
    return ((DimlavasmashState*)state)->state == 0;
}

typedef struct DimlavasmashObjectDef
{
    u8 pad0[0x18 - 0x0];
    s16 rotByte; /* 0x18 rotation byte (read raw as def[0x18] into anim.rotX) */
    s16 surfaceLayerId; /* 0x1A def source for state.surfaceLayerId */
    s16 unk1C;
    s16 gameBit;
} DimlavasmashObjectDef;

void dimlavasmash_init(s16* obj, s8* def)
{
    extern int* mapGetBlock(int idx);
    extern void dimlavasmash_setBlockSurfaceFlags(int* block, int mode, int v);
    ObjAnimComponent* objAnim;
    int* block;
    DimlavasmashState* inner;
    ObjHitsPriorityState* hitState;

    objAnim = (ObjAnimComponent*)obj;
    ((GameObject*)obj)->anim.rotX = (s16)((s32)def[0x18] << 8);
    ((GameObject*)obj)->animEventCallback = dimlavasmash_SeqFn;
    inner = ((GameObject*)obj)->extra;
    inner->surfaceLayerId = (u8)((DimlavasmashObjectDef*)def)->surfaceLayerId;
    inner->unk0 = (s8)((DimlavasmashObjectDef*)def)->unk1C;
    inner->state = GameBit_Get(((DimlavasmashObjectDef*)def)->gameBit);
    if (inner->state == 1)
    {
        block = mapGetBlock(objPosToMapBlockIdx(((GameObject*)obj)->anim.localPosX, ((GameObject*)obj)->anim.localPosY,
                                                ((GameObject*)obj)->anim.localPosZ));
        if (block != NULL)
        {
            dimlavasmash_setBlockSurfaceFlags(block, 1, inner->surfaceLayerId);
            dimlavasmash_setBlockSurfaceFlags(block, 0, inner->surfaceLayerId + 1);
        }
    }
    objAnim->bankIndex = def[0x19];
    hitState = (ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState;
    hitState->flags &= ~1;
    ((GameObject*)obj)->objectFlags = (u16)(((GameObject*)obj)->objectFlags | DIMLAVASMASH_OBJFLAG_HITDETECT_DISABLED);
}

void dimlavasmash_release(void)
{
}

void dimlavasmash_initialise(void)
{
}
