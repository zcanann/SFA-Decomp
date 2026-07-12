#include "main/audio/sfx.h"
#include "main/frame_timing.h"
#include "main/gamebits.h"
#include "main/gameplay_runtime.h"
#include "main/objanim_update.h"
#include "main/shader_api.h"
#include "main/lightmap_api.h"
#include "main/dll/WC/dll_0296_wctempledia.h"
#include "main/game_object.h"
#include "main/audio/sfx_ids.h"
#include "main/audio/sfx_trigger_ids.h"

#pragma dont_inline on

#define WCTEMPLE_DIA_EXTRA_SIZE       0x14
#define WCTEMPLE_DIA_STAGE_COUNT      3
#define WCTEMPLE_DIA_ALL_STAGES_MASK  7
#define WCTEMPLE_DIA_VISIBLE_OVERRIDE 0x100

#define WCTEMPLE_DIA_FLAG_SOLVED 1

#define WCTEMPLE_DIA_PAYLOAD_BLOCK_FLAG 2

#define WCTEMPLE_DIA_RESET_SFX 0x487
#define WCTEMPLE_DIA_STAGE_SFX 0x409

#define Sfx_SetObjectSfxVolumeIntVolume(obj, sfxId, volume, volumeScale)                                      \
    ((void (*)(u32, u32, int, f32))Sfx_SetObjectSfxVolume)((obj), (sfxId), (volume), (volumeScale))

void wctempledia_syncPartVisibility(GameObject* obj, u8 mask)
{
    int bit;
    int part;
    MapBlockData* block;
    int slot;

    block = mapGetBlock(objPosToMapBlockIdx(obj->anim.localPosX, obj->anim.localPosY, obj->anim.localPosZ));
    if (block != NULL)
    {
        for (part = 1; part < WCTEMPLE_DIA_STAGE_COUNT + 1; part++)
        {
            for (slot = 0, bit = mask & (1 << (part - 1)); slot < block->layerCount; slot++)
            {
                MapShader* entry = fn_8006070C(block, slot);
                if (*((u8*)entry + 0x29) == part)
                {
                    bit = mask & (1 << (part - 1));
                    if (bit != 0)
                    {
                        mapTextureOverrideSetValue(part, *(int*)((u8*)entry + 0x24), WCTEMPLE_DIA_VISIBLE_OVERRIDE);
                    }
                    else
                    {
                        mapTextureOverrideSetValue(part, *(int*)((u8*)entry + 0x24), 0);
                    }
                }
            }
        }
    }
}

int wctempledia_interactCallback(GameObject* obj, int unused, ObjAnimUpdateState* animUpdate)
{
    WCTempleDiaState* state = ((GameObject*)obj)->extra;

    {
        f32 scaled = gWcTempleDiaSpeedLerpRate;
        f32 cs = state->currentSpeed;
        scaled = scaled * -cs;
        state->currentSpeed = scaled * timeDelta + cs;
    }
    ((GameObject*)obj)->anim.rotZ = (s16)(timeDelta * state->currentSpeed + (f32)((GameObject*)obj)->anim.rotZ);
    animUpdate->sequenceEventActive = 0;
    animUpdate->activeHitVolumePair &= ~WCTEMPLE_DIA_PAYLOAD_BLOCK_FLAG;
    animUpdate->hitVolumePair &= ~WCTEMPLE_DIA_PAYLOAD_BLOCK_FLAG;
    return 0;
}

int wctempledia_getExtraSize(void)
{
    return WCTEMPLE_DIA_EXTRA_SIZE;
}

int wctempledia_getObjectTypeId(void)
{
    return 0;
}

void wctempledia_free(void)
{
}

void wctempledia_render(int obj, int p2, int p3, int p4, int p5, s8 visible)
{
    if (visible != 0)
    {
        objRenderModelAndHitVolumes(obj, p2, p3, p4, p5, lbl_803E6E58);
    }
}

void wctempledia_hitDetect(void)
{
}

void wctempledia_update(GameObject* obj)
{
    int i;
    WCTempleDiaState* state;
    WCTempleDiaSetup* setup;
    GameObject* go = (GameObject*)obj;
    int j;
    int k;

    state = go->extra;
    k = (u32)obj;
    setup = (WCTempleDiaSetup*)go->anim.placementData;

    if (state->flags & WCTEMPLE_DIA_FLAG_SOLVED)
    {
        wctempledia_syncPartVisibility((GameObject*)go, state->stageMask);
        return;
    }
    state->currentSpeed += timeDelta * (gWcTempleDiaSpeedLerpRate * (state->targetSpeed - state->currentSpeed));
    go->anim.rotZ = (s16)(timeDelta * state->currentSpeed + (f32)go->anim.rotZ);
    Sfx_KeepAliveLoopedObjectSound(k, SFXTRIG_en_treedrum16);
    {
        f32 ratio = state->currentSpeed / state->targetTable[2];
        Sfx_SetObjectSfxVolumeIntVolume((u32)go, SFXTRIG_en_treedrum16,
                                        (u8)(lbl_803E6E60 * ratio + lbl_803E6E5C),
                                        lbl_803E6E68 * ratio + lbl_803E6E64);
    }
    for (i = 0; i < WCTEMPLE_DIA_STAGE_COUNT; i++)
    {
        if ((state->stageMask & (1 << i)) == 0 && mainGetBit(state->gamebits[i]) != 0)
        {
            int found = 0;
            for (j = 0; j < i; j++)
            {
                if ((state->stageMask & (1 << j)) == 0)
                {
                    found = 1;
                    break;
                }
            }
            if (found)
            {
                for (k = 0; k < WCTEMPLE_DIA_STAGE_COUNT; k++)
                {
                    mainSetBits(state->gamebits[k], 0);
                }
                Sfx_PlayFromObject(0, WCTEMPLE_DIA_RESET_SFX);
                state->stageMask = 0;
                state->targetSpeed = state->targetTable[0];
                break;
            }
            state->stageMask |= (1 << i);
            if (i == 0)
            {
                state->targetSpeed = state->targetTable[1];
                Sfx_PlayFromObject(0, WCTEMPLE_DIA_STAGE_SFX);
            }
            else if (i == 1)
            {
                state->targetSpeed = state->targetTable[2];
                Sfx_PlayFromObject(0, WCTEMPLE_DIA_STAGE_SFX);
            }
        }
    }
    wctempledia_syncPartVisibility((GameObject*)go, state->stageMask);
    if (state->stageMask == WCTEMPLE_DIA_ALL_STAGES_MASK)
    {
        mainSetBits(setup->solvedBit, 1);
        Sfx_PlayFromObject(0, SFXTRIG_mpick1_b);
        state->flags |= WCTEMPLE_DIA_FLAG_SOLVED;
    }
}

void wctempledia_init(GameObject* obj, WCTempleDiaSetup* setup)
{
    ObjAnimComponent* objAnim = (ObjAnimComponent*)obj;
    WCTempleDiaState* state = ((GameObject*)obj)->extra;
    int i;

    ((GameObject*)obj)->anim.rotX = (s16)(setup->type << 8);
    *(u8*)&objAnim->bankIndex = setup->modelIndex;
    if (objAnim->bankIndex >= objAnim->modelInstance->modelCount)
    {
        objAnim->bankIndex = 0;
    }
    if (objAnim->bankIndex == 0)
    {
        state->gamebits = gWcTempleDiaGameBitsA;
        state->targetTable = gWcTempleDiaTargetSpeedTableA;
    }
    else
    {
        state->gamebits = gWcTempleDiaGameBitsB;
        state->targetTable = gWcTempleDiaTargetSpeedTableB;
    }
    for (i = 0; i < WCTEMPLE_DIA_STAGE_COUNT; i++)
    {
        if ((u32)mainGetBit(state->gamebits[i]) != 0)
        {
            state->stageMask |= (1 << i);
        }
    }
    if ((u32)mainGetBit(setup->solvedBit) != 0)
    {
        state->stageMask = WCTEMPLE_DIA_ALL_STAGES_MASK;
        state->flags |= WCTEMPLE_DIA_FLAG_SOLVED;
    }
    if (state->stageMask & 2)
    {
        state->currentSpeed = state->targetTable[2];
    }
    else if (state->stageMask & 1)
    {
        state->currentSpeed = state->targetTable[1];
    }
    else
    {
        state->currentSpeed = state->targetTable[0];
    }
    state->targetSpeed = state->currentSpeed;
    ((GameObject*)obj)->animEventCallback = wctempledia_interactCallback;
    wctempledia_syncPartVisibility((GameObject*)(obj), state->stageMask);
}

void wctempledia_release(void)
{
}

void wctempledia_initialise(void)
{
}

f32 gWcTempleDiaTargetSpeedTableA[] = {64.0f, 128.0f, 256.0f};
f32 gWcTempleDiaTargetSpeedTableB[] = {-64.0f, -128.0f, -256.0f};
