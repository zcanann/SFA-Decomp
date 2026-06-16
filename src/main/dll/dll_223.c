/*
 * DIMbosstonsil (DLL 0x223): the "tonsil" boss creature inhabiting the
 * DIM-temple area. It is a stationary, multi-phase boss the player damages in
 * a fixed sequence; each qualifying hit advances its route phase until it is
 * defeated. This unit implements the boss's hit-reaction lifecycle - how it
 * acknowledges, animates, and progresses through damage when the player lands
 * an attack on one of its model parts.
 */
#include "main/game_object.h"
#include "main/dll/DIM/dll_223.h"
#include "main/effect_interfaces.h"
#include "main/objhits.h"
#include "main/objfx.h"
#include "main/player_control_interface.h"

extern int GameBit_Set(int eventId, int value);
extern void CameraShake_SetAllMagnitudes(f32 magnitude);
extern void* Obj_GetPlayerObject(void);
extern void Sfx_PlayFromObject(void* obj, int sfxId);
extern void doRumble(f32 val);
extern void ObjMsg_SendToObject(void* obj, int msg, void* sender, int param_4);

extern void* gBaddieControlInterface;
extern f32 lbl_803DDB98;
extern f32 lbl_803DDB9C;
extern f32 lbl_803DDBA0;
extern f32 lbl_803E4C90;
extern f32 lbl_803E4C94;
extern f32 lbl_803E4C98;
extern f32 lbl_803E4CA4;
extern f32 lbl_803E4CA8;
extern f32 lbl_803E4CAC;
extern f32 lbl_803E4CB0;
extern f32 playerMapOffsetX;
extern f32 playerMapOffsetZ;

#define DIMBOSSTONSIL_HIT_EFFECT_ID 0x4b2
#define DIMBOSSTONSIL_HIT_EFFECT_ALT_ID 0x4b3
#define DIMBOSSTONSIL_PRIMARY_HIT_SFX 0x18a
#define DIMBOSSTONSIL_ALT_HIT_SFX 0x18b
#define DIMBOSSTONSIL_NORMAL_HIT_SFX 0x18c
#define DIMBOSSTONSIL_HIT_GAMEBIT 0x20c
#define DIMBOSSTONSIL_ADVANCE_MSG 0xe0001
/* particle-spawn flag word: bit 0x200000 | bit 0x1 */
#define DIMBOSSTONSIL_HIT_FX_FLAGS 0x200001

int DIMbosstonsil_updateHitReaction(void* obj, DIMbosstonsilState* state, int param_3)
{
    if (state->active != 0)
    {
        (*gPlayerInterface)->setState(obj, state, 1);
    }
    if (state->hitResult != 0)
    {
        return 1;
    }
    return 0;
}

int DIMbosstonsil_enableHitReaction(void* obj, DIMbosstonsilState* state)
{
    if (state->stunReady != 0)
    {
        state->active = 1;
        (*gPlayerInterface)->setState(obj, state, 0);
    }
    return 0;
}

int DIMbosstonsil_chooseHitReaction(void* obj, DIMbosstonsilState* state)
{
    u16 moveId;
    s16 unused1;
    s16 unused2;

    if (state->active != 0)
    {
        lbl_803DDB9C = lbl_803DDBA0;
        (*(void (***)(void*, void*, int, u16*, s16*, s16*))gBaddieControlInterface)[5]
            (obj, Obj_GetPlayerObject(), 4, &moveId, &unused1, &unused2);
        switch (moveId)
        {
        case 0:
            if (state->active != 0)
            {
                ObjAnim_SetCurrentMove((int)obj, 1, lbl_803E4C90, 0);
                state->hitResult = 0;
            }
            break;
        case 1:
            if (state->active != 0)
            {
                ObjAnim_SetCurrentMove((int)obj, 3, lbl_803E4C90, 0);
                state->hitResult = 0;
            }
            break;
        case 2:
            if (state->active != 0)
            {
                ObjAnim_SetCurrentMove((int)obj, 2, lbl_803E4C90, 0);
                state->hitResult = 0;
            }
            break;
        default:
            if (state->active != 0)
            {
                ObjAnim_SetCurrentMove((int)obj, 4, lbl_803E4C90, 0);
                state->hitResult = 0;
            }
            break;
        }
        state->recoveryTimer = lbl_803E4C94;
    }
    return 0;
}

int DIMbosstonsil_startIdleHitReaction(void* obj, DIMbosstonsilState* state)
{
    if (state->active != 0)
    {
        ObjAnim_SetCurrentMove((int)obj, 0, lbl_803E4C90, 0);
        state->hitResult = 0;
    }
    state->recoveryTimer = lbl_803E4C98;
    return 0;
}

void DIMbosstonsil_checkHit(void* obj, DIMbosstonsilState* state)
{
    int hitObj;
    int modelPart;
    uint hitVolume;
    undefined4 spawnArgs[7];
    f32* spawnPos;
    int hit;

    hit = ObjHits_GetPriorityHit((int)obj, &hitObj, &modelPart, &hitVolume);
    if (hit != 0)
    {
        spawnPos = (f32*)((char*)spawnArgs + 0xc);
        {
            /* modelPos is a 4-float per-part record; index 0 is skipped (x/y/z live at 1/2/3) */
            f32* modelPos = (f32*)(*(int*)(*(int*)(*(int*)&((GameObject*)obj)->anim.banks +
                ((s8)((u8*)obj)[0xad] << 2)) + 0x50) + modelPart * 0x10);
            spawnPos[0] = playerMapOffsetX + modelPos[1];
            spawnPos[1] = modelPos[2];
            spawnPos[2] = playerMapOffsetZ + modelPos[3];
        }
        (*gPartfxInterface)->spawnObject(obj, DIMBOSSTONSIL_HIT_EFFECT_ID, spawnArgs, DIMBOSSTONSIL_HIT_FX_FLAGS, -1, NULL);
        (*gPartfxInterface)->spawnObject(obj, DIMBOSSTONSIL_HIT_EFFECT_ALT_ID, spawnArgs, DIMBOSSTONSIL_HIT_FX_FLAGS, -1, NULL);
        objLightFn_8009a1dc(obj, lbl_803E4CA4, spawnArgs, 3, 0);
        Sfx_PlayFromObject(obj, DIMBOSSTONSIL_PRIMARY_HIT_SFX);
        doRumble(lbl_803E4CA8);
        if (state->hitPointsLeft != 0)
        {
            Sfx_PlayFromObject(obj, DIMBOSSTONSIL_ALT_HIT_SFX);
        }
        else
        {
            Sfx_PlayFromObject(obj, DIMBOSSTONSIL_NORMAL_HIT_SFX);
        }
        CameraShake_SetAllMagnitudes(lbl_803E4CAC);
        if (lbl_803E4C90 == lbl_803DDB98)
        {
            state->active = 1;
            state->hitResult = 0;
            state->hitDamageCount = hit;
            state->hitPointsLeft--;
            gDIMbosstonsilRoutePhase++;
            GameBit_Set(DIMBOSSTONSIL_HIT_GAMEBIT, gDIMbosstonsilRoutePhase);
            if (gDIMbosstonsilRoutePhase == 3 || gDIMbosstonsilRoutePhase == 7)
            {
                lbl_803DDB98 = lbl_803E4CB0;
            }
            else
            {
                lbl_803DDB98 = lbl_803E4C90;
            }
            (*gPlayerInterface)->setState(obj, state, 1);
            state->field270 = 1;
            ObjMsg_SendToObject((void*)hitObj, DIMBOSSTONSIL_ADVANCE_MSG, obj, 0);
        }
    }
}
