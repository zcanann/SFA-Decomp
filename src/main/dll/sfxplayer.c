#include "ghidra_import.h"
#include "main/dll/sfxplayer.h"

extern void Obj_FreeObject(int obj);
extern int ObjHits_GetPriorityHit(int obj,undefined4 *outHitObject,int *outSphereIndex,uint *outHitVolume);
extern void Sfx_PlayFromObject(int obj,int sfxId);
extern void GameBit_Set(int eventId,int value);
extern void gameTimerStop(void);
extern void gameTimerInit(int timerId,int frames);
extern u32 GameBit_Get(int eventId);
extern int isGameTimerDisabled(void);
extern void timerSetToCountUp(void);
extern void TrickyCurve_activateEffectHandleRing(void);
extern void TrickyCurve_updateEffectHandleRing(int obj);

extern undefined4* lbl_803DCAAC;

#define SFXPLAYER_OBJECT_MAP_ID_OFFSET 0xAC
#define SFXPLAYER_OBJECT_FLAGS_OFFSET 0xB0
#define SFXPLAYER_OBJECT_STATE_OFFSET 0xB8
#define SFXPLAYER_OBJECT_CALLBACK_OFFSET 0xBC
#define SFXPLAYER_CONFIG_MAP_ID_OFFSET 0x18
#define SFXPLAYER_CONFIG_MODE_OFFSET 0x19
#define SFXPLAYER_CONFIG_EVENT_ID_OFFSET 0x1E
#define SFXPLAYER_CONFIG_FIELD20_OFFSET 0x20
#define SFXPLAYER_EFFECT_RING_COUNT 4
#define SFXPLAYER_EFFECT_HANDLES_PER_RING 2
#define SFXPLAYER_COMPLETE_RING_COUNT 4
#define SFXPLAYER_TIMER_ID 0x1D
#define SFXPLAYER_TIMER_SHORT_FRAMES 0x96
#define SFXPLAYER_TIMER_LONG_FRAMES 0xB4
#define SFXPLAYER_MODE_SINGLE 1
#define SFXPLAYER_GAMEBIT_RING_ACTIVE 0xEDF
#define SFXPLAYER_GAMEBIT_SINGLE_COMPLETE 0x9F7
#define SFXPLAYER_SFX_COMPLETE 0x7E
#define SFXPLAYER_SFX_TIMEOUT_RESET 0x1CE
#define SFXPLAYER_SFX_RING_HIT 0x409
#define SFXPLAYER_HIT_TYPE_RING_TARGET 0x13
#define SFXPLAYER_OBJECT_FLAGS 0x6000

/*
 * --INFO--
 *
 * Function: sfxplayer_update
 * EN v1.0 Address: 0x80207CE4
 * EN v1.0 Size: 720b
 * EN v1.1 Address: 0x80207F80
 * EN v1.1 Size: 492b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void sfxplayer_update(int obj)
{
  s16 i;
  s16 hitType;
  u8 mode;
  SfxplayerState *state;
  uint *handles;
  SfxplayerStateFlags *flags;
  undefined4 hitObj;
  
  state = *(SfxplayerState **)(obj + SFXPLAYER_OBJECT_STATE_OFFSET);
  flags = &state->flags;
  if ((flags->bit20 == 0) && (GameBit_Get(state->eventId) == 0)) {
    if (state->ringCount == SFXPLAYER_COMPLETE_RING_COUNT) {
      Sfx_PlayFromObject(0,SFXPLAYER_SFX_COMPLETE);
      flags->bit20 = 1;
      flags->bit10 = 0;
      flags->bit40 = 0;
      GameBit_Set(state->eventId,1);
      GameBit_Set(SFXPLAYER_GAMEBIT_RING_ACTIVE,0);
      mode = (*(code *)(*lbl_803DCAAC + 0x40))((int)*(char *)(obj + SFXPLAYER_OBJECT_MAP_ID_OFFSET));
      if (mode == SFXPLAYER_MODE_SINGLE) {
        GameBit_Set(SFXPLAYER_GAMEBIT_SINGLE_COMPLETE,1);
      }
      gameTimerStop();
    }
    else {
      if (flags->bit80 != 0) {
        flags->bit80 = 0;
        if (flags->bit10 != 0) {
          mode = (*(code *)(*lbl_803DCAAC + 0x40))((int)*(char *)(obj + SFXPLAYER_OBJECT_MAP_ID_OFFSET));
          if (mode == SFXPLAYER_MODE_SINGLE) {
            gameTimerInit(SFXPLAYER_TIMER_ID,SFXPLAYER_TIMER_SHORT_FRAMES);
          }
          else {
            gameTimerInit(SFXPLAYER_TIMER_ID,SFXPLAYER_TIMER_LONG_FRAMES);
          }
          timerSetToCountUp();
        }
      }
      if (isGameTimerDisabled() != 0) {
        handles = (uint *)gSfxplayerEffectHandles;
        for (i = 0; i < SFXPLAYER_EFFECT_RING_COUNT; i++) {
          if (handles[0] != 0) {
            Obj_FreeObject(handles[0]);
          }
          handles[0] = 0;
          if (handles[1] != 0) {
            Obj_FreeObject(handles[1]);
          }
          handles[1] = 0;
          Sfx_PlayFromObject(obj,SFXPLAYER_SFX_TIMEOUT_RESET);
          handles += SFXPLAYER_EFFECT_HANDLES_PER_RING;
        }
        state->ringCount = 0;
        flags->bit40 = 0;
        flags->bit10 = 0;
        GameBit_Set(SFXPLAYER_GAMEBIT_RING_ACTIVE,0);
      }
      TrickyCurve_updateEffectHandleRing(obj);
      handles = (uint *)gSfxplayerEffectHandles;
      for (i = 0; i < SFXPLAYER_EFFECT_RING_COUNT; i++) {
        if (handles[0] != 0) {
          hitObj = 0;
          hitType = ObjHits_GetPriorityHit(handles[1],&hitObj,(int *)0x0,(uint *)0x0);
          if (hitType == SFXPLAYER_HIT_TYPE_RING_TARGET) {
            mode = (*(code *)(*lbl_803DCAAC + 0x40))((int)*(char *)(obj + SFXPLAYER_OBJECT_MAP_ID_OFFSET));
            if ((mode == SFXPLAYER_MODE_SINGLE) || (*(int *)((int)hitObj + 0xf4) == i)) {
              if (handles[0] != 0) {
                Obj_FreeObject(handles[0]);
              }
              handles[0] = 0;
              if (handles[1] != 0) {
                Obj_FreeObject(handles[1]);
              }
              handles[1] = 0;
              Sfx_PlayFromObject(0,SFXPLAYER_SFX_RING_HIT);
              state->ringCount++;
            }
          }
        }
        handles += SFXPLAYER_EFFECT_HANDLES_PER_RING;
      }
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: sfxplayer_init
 * EN v1.0 Address: 0x80207FBC
 * EN v1.0 Size: 212b
 * EN v1.1 Address: 0x8020816C
 * EN v1.1 Size: 212b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off
void sfxplayer_init(int obj,int config)
{
  SfxplayerState *state;

  state = *(SfxplayerState **)(obj + SFXPLAYER_OBJECT_STATE_OFFSET);
  *(s16 *)obj = (s16)((s8)*(u8 *)(config + SFXPLAYER_CONFIG_MAP_ID_OFFSET) << 8);
  *(void (**)(void))(obj + SFXPLAYER_OBJECT_CALLBACK_OFFSET) = TrickyCurve_activateEffectHandleRing;
  state->config19 = *(u8 *)(config + SFXPLAYER_CONFIG_MODE_OFFSET);
  state->eventId = *(s16 *)(config + SFXPLAYER_CONFIG_EVENT_ID_OFFSET);
  state->unk2 = *(s16 *)(config + SFXPLAYER_CONFIG_FIELD20_OFFSET);
  state->unk4 = 1;
  gSfxplayerEffectHandles[0] = 0;
  gSfxplayerEffectHandles[1] = 0;
  gSfxplayerEffectHandles[2] = 0;
  gSfxplayerEffectHandles[3] = 0;
  gSfxplayerEffectHandles[4] = 0;
  gSfxplayerEffectHandles[5] = 0;
  gSfxplayerEffectHandles[6] = 0;
  gSfxplayerEffectHandles[7] = 0;
  gameTimerStop();
  if (GameBit_Get(state->eventId) != 0) {
    state->flags.bit20 = 1;
  }
  *(u16 *)(obj + SFXPLAYER_OBJECT_FLAGS_OFFSET) =
      *(u16 *)(obj + SFXPLAYER_OBJECT_FLAGS_OFFSET) | SFXPLAYER_OBJECT_FLAGS;
}
#pragma peephole reset
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: sfxplayer_release
 * EN v1.0 Address: 0x80208090
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80208240
 * EN v1.1 Size: 4b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void sfxplayer_release(void)
{
}

/*
 * --INFO--
 *
 * Function: sfxplayer_initialise
 * EN v1.0 Address: 0x80208094
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80208244
 * EN v1.1 Size: 4b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void sfxplayer_initialise(void)
{
}
