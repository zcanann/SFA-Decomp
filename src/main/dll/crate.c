#include "ghidra_import.h"
#include "main/dll/crate.h"

extern undefined4 FUN_80006824();
extern undefined4 FUN_80006b4c();
extern undefined4 FUN_80017ac8();
extern void GameBit_Set(int eventId,int value);
extern int gSfxplayerEffectHandles[8];

#define SFXPLAYER_EVENT_ACTIVATE 1
#define SFXPLAYER_EVENT_DEACTIVATE 2
#define SFXPLAYER_EVENT_VARIANT 3
#define SFXPLAYER_VARIANT_TIMER_FRAMES 0x96

typedef struct SfxplayerState {
  s16 unused0;
  s16 effectSfxBaseId;
  s16 variantSfxTimer;
  u8 unused6[2];
  u8 effectFlags;
} SfxplayerState;

/*
 * --INFO--
 *
 * Function: sfxplayer_updateState
 * EN v1.0 Address: 0x80208098
 * EN v1.0 Size: 328b
 * EN v1.1 Address: 0x8020816C
 * EN v1.1 Size: 256b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma peephole off
undefined4 sfxplayer_updateState(int obj,undefined4 param_2,int hitState)
{
  int event;
  SfxplayerState *state;
  int i;

  state = *(SfxplayerState **)(obj + 0xb8);
  *(s16 *)(hitState + 0x6e) = -1;
  *(u8 *)(hitState + 0x56) = 0;
  i = 0;
  while (i < (int)*(u8 *)(hitState + 0x8b)) {
    event = *(u8 *)(hitState + i + 0x81);
    switch (event) {
    case SFXPLAYER_EVENT_ACTIVATE:
      GameBit_Set(state->effectSfxBaseId + 5,1);
      break;
    case SFXPLAYER_EVENT_DEACTIVATE:
      GameBit_Set(state->effectSfxBaseId + 5,0);
      state->effectFlags = 1;
      break;
    case SFXPLAYER_EVENT_VARIANT:
      switch (state->effectSfxBaseId) {
      case 0x672:
        GameBit_Set(0x66e,1);
        state->variantSfxTimer = SFXPLAYER_VARIANT_TIMER_FRAMES;
        break;
      case 0x673:
        GameBit_Set(0x66f,1);
        state->variantSfxTimer = SFXPLAYER_VARIANT_TIMER_FRAMES;
        break;
      case 0x674:
        GameBit_Set(0x670,1);
        state->variantSfxTimer = SFXPLAYER_VARIANT_TIMER_FRAMES;
        break;
      case 0x675:
        GameBit_Set(0x9f5,1);
        state->variantSfxTimer = SFXPLAYER_VARIANT_TIMER_FRAMES;
        break;
      }
      break;
    }
    *(u8 *)(hitState + i + 0x81) = 0;
    i++;
  }
  return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_802081e0
 * EN v1.0 Address: 0x802081E0
 * EN v1.0 Size: 352b
 * EN v1.1 Address: 0x8020826C
 * EN v1.1 Size: 176b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_802081e0(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 uint param_9,int param_10)
{
  short sVar1;
  int *piVar2;
  
  if (param_10 == 0) {
    piVar2 = gSfxplayerEffectHandles;
    for (sVar1 = 0; sVar1 < 4; sVar1 = sVar1 + 1) {
      if (*piVar2 != 0) {
        param_1 = FUN_80017ac8(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                               *piVar2);
      }
      *piVar2 = 0;
      if (piVar2[1] != 0) {
        FUN_80017ac8(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,piVar2[1]);
      }
      piVar2[1] = 0;
      param_1 = FUN_80006824(param_9,0x1ce);
      piVar2 = piVar2 + 2;
    }
  }
  FUN_80006b4c();
  return;
}
