#include "ghidra_import.h"
#include "main/mapEvent.h"
#include "main/dll/DIM/DIMbosstonsil.h"


#pragma peephole off
#pragma scheduling off
extern void Music_Trigger(s32 triggerId,s32 mode);
extern uint GameBit_Get(int eventId);
extern void modelLightStruct_getSpecularColor(void *light,void *red,void *green,void *blue,void *alpha);
extern void modelLightStruct_setGlowColor(void *light,u8 red,u8 green,u8 blue,int alpha);
extern int randomGetRange(int min,int max);
extern void skyFn_80089710(int id,int enabled,int arg);
extern void skyFn_800894a8(int id,f32 x,f32 y,f32 z);
extern void skyFn_800895e0(int id,int red,int green,int blue,int alpha,int arg);
extern void getEnvfxAct(void *obj,void *source,int effectId,int arg);
extern void Sfx_PlayFromObject(void *obj,int sfxId);
extern void doRumble(f32 strength);
extern void modelLightStruct_setEnabled(void *light,int enabled,f32 value);
extern int dimBossTonsil_newState_hitFightMain(void *obj,ObjAnimUpdateState *animUpdate,
                                                DIMbosstonsilState *state,
                                                DIMbosstonsilState *updateState);
extern void ObjGroup_RemoveObject(void *obj,int group);
extern void ModelLightStruct_free(void *light);

extern MapEventInterface **gMapEventInterface;
extern void *gObjectTriggerInterface;
extern void *gBaddieControlInterface;
extern void *gPlayerInterface;
extern f32 timeDelta;
extern u8 lbl_803DDBA8;
extern u8 lbl_803DDBB0;
extern f32 lbl_803DDB9C;
extern f32 lbl_803DDBA0;
extern f32 lbl_803E4C90;
extern f32 lbl_803E4CB8;
extern f32 lbl_803E4CBC;
extern f32 lbl_803E4CC0;
extern f32 lbl_803E4CC4;

/*
 * --INFO--
 *
 * Function: dll_DIM_BossGutSpik_update
 * EN v1.0 Address: 0x801BE44C
 * EN v1.0 Size: 804b
 * EN v1.1 Address: 0x801BE750
 * EN v1.1 Size: 688b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int dll_DIM_BossGutSpik_update(void *obj,undefined4 param_2,ObjAnimUpdateState *animUpdate)
{
  DIMbosstonsilState *state;
  DIMbosstonsilConfig *config;
  u8 red;
  u8 green;
  u8 blue;
  u8 alpha;
  s16 lightValue;
  int eventIndex;
  int eventId;
  int hitReactMode;
  int animOk;

  state = *(DIMbosstonsilState **)((u8 *)obj + 0xb8);
  config = *(DIMbosstonsilConfig **)((u8 *)obj + 0x4c);

  if (gDIMbosstonsilLight != NULL) {
    modelLightStruct_getSpecularColor(gDIMbosstonsilLight,&red,&green,&blue,&alpha);
    modelLightStruct_setGlowColor(gDIMbosstonsilLight,red,green,blue,0xc0);
    if (gDIMbosstonsilLight->active != 0 && gDIMbosstonsilLight->visible != 0) {
      lightValue = gDIMbosstonsilLight->glowIntensity + gDIMbosstonsilLight->glowIntensityStep;
      if (lightValue < 0) {
        lightValue = 0;
        gDIMbosstonsilLight->glowIntensityStep = 0;
      } else if (lightValue > 0xc) {
        lightValue = lightValue + randomGetRange(-0xc,0xc);
        if (lightValue > 0xff) {
          lightValue = 0xff;
          gDIMbosstonsilLight->glowIntensityStep = 0;
        }
      }
      gDIMbosstonsilLight->glowIntensity = (u8)lightValue;
    }
  }

  if (*(int *)((u8 *)obj + 0xf4) != 0) {
    return 0;
  }

  for (eventIndex = 0; eventIndex < (int)(u32)animUpdate->eventCount; eventIndex++) {
    eventId = animUpdate->eventIds[eventIndex];
    switch (eventId) {
    case DIMBOSSTONSIL_ANIM_EVENT_START_STEAM:
      skyFn_80089710(7,1,0);
      skyFn_800894a8(7,lbl_803E4CC4,lbl_803E4CC4,lbl_803E4CB8);
      skyFn_800895e0(7,0xff,0xb4,0xb4,0x7f,0x28);
      getEnvfxAct(obj,obj,DIMBOSSTONSIL_STEAM_ENVFX,0);
      Music_Trigger(DIMBOSSTONSIL_STEAM_MUSIC,1);
      break;
    case DIMBOSSTONSIL_ANIM_EVENT_ENABLE_AREA:
      (*gMapEventInterface)->setAnimEvent(DIMBOSSTONSIL_MAP_DIR,DIMBOSSTONSIL_MAP_AREA,1);
      break;
    case DIMBOSSTONSIL_ANIM_EVENT_DISABLE_AREA:
      (*gMapEventInterface)->setAnimEvent(DIMBOSSTONSIL_MAP_DIR,DIMBOSSTONSIL_MAP_AREA,0);
      break;
    case DIMBOSSTONSIL_ANIM_EVENT_ENABLE_LIGHT:
      if (gDIMbosstonsilLight != NULL) {
        modelLightStruct_setEnabled(gDIMbosstonsilLight,1,lbl_803E4CB8);
      }
      break;
    case DIMBOSSTONSIL_ANIM_EVENT_DISABLE_LIGHT:
      if (gDIMbosstonsilLight != NULL) {
        modelLightStruct_setEnabled(gDIMbosstonsilLight,0,lbl_803E4CB8);
      }
      break;
    }
  }

  if (lbl_803DDBA0 >= lbl_803DDB9C) {
    Sfx_PlayFromObject(obj,DIMBOSSTONSIL_RUMBLE_SFX);
    lbl_803DDB9C += lbl_803E4CBC;
    doRumble(lbl_803E4CC0);
  }
  lbl_803DDBA0 += timeDelta;

  if (*(s16 *)((u8 *)obj + 0xb4) != -1) {
    animOk = (*(int (**)(void *,DIMbosstonsilState *,int))(*(int *)gBaddieControlInterface + 0x30))
        (obj,state,1);
    if (animOk == 0) {
      return 1;
    }
    if ((state->eventGameBit != -1) &&
        (GameBit_Get(state->eventGameBit) != 0)) {
      (*(void (**)(ObjAnimUpdateState *,int))(*(int *)gObjectTriggerInterface + 0x58))
          (animUpdate,(int)config->eventId);
      state->eventGameBit = -1;
    }

    hitReactMode = state->hitReactMode;
    if (hitReactMode == 1) {
      goto updateHitReaction;
    }
    if (hitReactMode < 1 || hitReactMode >= 3) {
      goto clearHitVolumePair;
    }
    animUpdate->hitVolumePair = 0;
    dimBossTonsil_newState_hitFightMain(obj,animUpdate,state,state);
    if (state->hitReactMode == 1) {
      state->field270 = 0;
      (*(void (**)(void *,DIMbosstonsilState *,f32,f32,u8 *,u8 *))(*(int *)gPlayerInterface + 0x8))
          (obj,state,lbl_803E4CB8,lbl_803E4CB8,&lbl_803DDBB0,&lbl_803DDBA8);
      animUpdate->sequenceEventActive = 0;
    }
    goto updateDone;

updateHitReaction:
      animOk = (*(int (**)(void *,ObjAnimUpdateState *,DIMbosstonsilState *,u8 *,u8 *,int))
                (*(int *)gBaddieControlInterface + 0x34))
          (obj,animUpdate,state,&lbl_803DDBB0,&lbl_803DDBA8,0);
      if (animOk != 0) {
        (*(void (**)(void *,DIMbosstonsilState *,f32,int))(*(int *)gBaddieControlInterface + 0x2c))
            (obj,state,lbl_803E4C90,1);
      }
    goto updateDone;

clearHitVolumePair:
      animUpdate->hitVolumePair = -1;
      animUpdate->hitVolumePair &= ~0x40;

updateDone:;
  }

  if (*(s16 *)((u8 *)obj + 0xb4) == -1) {
    state->stateFlags |= DIMBOSSTONSIL_STATE_FLAG_START_MOVE;
    return 0;
  }

  return 0;
}

/*
 * --INFO--
 *
 * Function: DIMbosstonsil_func0B
 * EN v1.0 Address: 0x801BE86C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void DIMbosstonsil_func0B(void)
{
}

/*
 * --INFO--
 *
 * Function: DIMbosstonsil_setScale
 * EN v1.0 Address: 0x801BE870
 * EN v1.0 Size: 12b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int DIMbosstonsil_setScale(int obj)
{
  return (*(DIMbosstonsilState **)(obj + 0xb8))->scale;
}

/*
 * --INFO--
 *
 * Function: DIMbosstonsil_getExtraSize
 * EN v1.0 Address: 0x801BE87C
 * EN v1.0 Size: 8b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int DIMbosstonsil_getExtraSize(void)
{
  return DIMBOSSTONSIL_STATE_SIZE;
}

/*
 * --INFO--
 *
 * Function: DIMbosstonsil_getObjectTypeId
 * EN v1.0 Address: 0x801BE884
 * EN v1.0 Size: 8b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int DIMbosstonsil_getObjectTypeId(void)
{
  return DIMBOSSTONSIL_OBJECT_TYPE;
}

/*
 * --INFO--
 *
 * Function: DIMbosstonsil_free
 * EN v1.0 Address: 0x801BE88C
 * EN v1.0 Size: 108b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void DIMbosstonsil_free(void *obj)
{
  DIMbosstonsilState *state;

  state = *(DIMbosstonsilState **)((u8 *)obj + 0xb8);
  ObjGroup_RemoveObject(obj,3);
  (*(void (**)(void *,DIMbosstonsilState *,int))(*(int *)gBaddieControlInterface + 0x40))(obj,state,1);
  if (gDIMbosstonsilLight != NULL) {
    ModelLightStruct_free(gDIMbosstonsilLight);
  }
}
