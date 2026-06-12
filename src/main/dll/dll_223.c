#include "main/game_object.h"
#include "main/dll/DIM/dll_223.h"
#include "main/effect_interfaces.h"
#include "main/objfx.h"

extern undefined4 GameBit_Set(int eventId, int value);
extern void CameraShake_SetAllMagnitudes(f32 magnitude);
extern void* Obj_GetPlayerObject(void);
extern int ObjHits_GetPriorityHit(void* obj, void** hitObj, int* outModelPart, int* outIndex);
extern void Sfx_PlayFromObject(void* obj, int sfxId);
extern void doRumble(f32 val);
extern void ObjMsg_SendToObject(void* obj, int msg, void* sender, int param_4);

extern void* gPlayerInterface;
extern void* gBaddieControlInterface;
extern f32 lbl_803DDB98;
extern f32 lbl_803DDB9C;
extern f32 lbl_803DDBA0;
extern EffectInterface** gPartfxInterface;
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

int DIMbosstonsil_updateHitReaction(void* obj, DIMbosstonsilState* state, int param_3)
{
    if (state->active != 0)
    {
        (*(void (***)(void*, DIMbosstonsilState*, int))gPlayerInterface)[5](obj, state, 1);
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
        (*(void (***)(void*, DIMbosstonsilState*, int))gPlayerInterface)[5](obj, state, 0);
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
    void* hitObj;
    int modelPart;
    int unused;
    undefined4 effect[7];
    f32* pos;
    int hit;

    hit = ObjHits_GetPriorityHit(obj, &hitObj, &modelPart, &unused);
    if (hit != 0)
    {
        pos = (f32*)((char*)effect + 0xc);
        {
            f32* modelPos = (f32*)(*(int*)(*(int*)(*(int*)&((GameObject*)obj)->anim.banks +
                ((s8)((u8*)obj)[0xad] << 2)) + 0x50) + modelPart * 0x10);
            pos[0] = playerMapOffsetX + modelPos[1];
            pos[1] = modelPos[2];
            pos[2] = playerMapOffsetZ + modelPos[3];
        }
        (*gPartfxInterface)->spawnObject(obj, DIMBOSSTONSIL_HIT_EFFECT_ID, effect, 0x200001, -1, NULL);
        (*gPartfxInterface)->spawnObject(obj, DIMBOSSTONSIL_HIT_EFFECT_ALT_ID, effect, 0x200001, -1, NULL);
        objLightFn_8009a1dc(obj, lbl_803E4CA4, effect, 3, 0);
        Sfx_PlayFromObject(obj,DIMBOSSTONSIL_PRIMARY_HIT_SFX);
        doRumble(lbl_803E4CA8);
        if (state->hitPointsLeft != 0)
        {
            Sfx_PlayFromObject(obj,DIMBOSSTONSIL_ALT_HIT_SFX);
        }
        else
        {
            Sfx_PlayFromObject(obj,DIMBOSSTONSIL_NORMAL_HIT_SFX);
        }
        CameraShake_SetAllMagnitudes(lbl_803E4CAC);
        if (lbl_803E4C90 == lbl_803DDB98)
        {
            state->active = 1;
            state->hitResult = 0;
            state->hitDamageCount = hit;
            state->hitPointsLeft--;
            gDIMbosstonsilRoutePhase++;
            GameBit_Set(DIMBOSSTONSIL_HIT_GAMEBIT, *(s8*)&gDIMbosstonsilRoutePhase);
            if (gDIMbosstonsilRoutePhase == 3 || gDIMbosstonsilRoutePhase == 7)
            {
                lbl_803DDB98 = lbl_803E4CB0;
            }
            else
            {
                lbl_803DDB98 = lbl_803E4C90;
            }
            (*(void (***)(void*, DIMbosstonsilState*, int))gPlayerInterface)[5](obj, state, 1);
            state->field270 = 1;
            ObjMsg_SendToObject(hitObj,DIMBOSSTONSIL_ADVANCE_MSG, obj, 0);
        }
    }
}
