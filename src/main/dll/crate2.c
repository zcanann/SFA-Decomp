#include "ghidra_import.h"
#include "main/dll/crate2.h"

extern undefined8 FUN_80006824();
extern byte FUN_80006b44();
extern undefined4 FUN_80006b4c();
extern undefined8 FUN_80006b50();
extern undefined4 FUN_80006b54();
extern uint FUN_80017690();
extern undefined4 FUN_80017698();
extern undefined8 FUN_80017ac8();
extern int ObjHits_GetPriorityHit();
extern undefined4 FUN_80286840();
extern undefined4 FUN_8028688c();

extern int gSfxplayerEffectHandles[8];
extern undefined4* DAT_803dd72c;
extern undefined4 sfxplayer_updateEffectHandlePositions();

typedef struct DfpStatue1State {
  s16 triggerSfxId;
  s16 loopSfxId;
  s16 loopSfxStopTimer;
  u8 loopActive;
  u8 effectPairCount;
  u8 stateFlags;
} DfpStatue1State;

/*
 * --INFO--
 *
 * Function: dfpstatue1_updateState
 * EN v1.0 Address: 0x802081F4
 * EN v1.0 Size: 1128b
 * EN v1.1 Address: 0x8020831C
 * EN v1.1 Size: 728b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void dfpstatue1_updateState(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                            undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
  short *psVar1;
  uint uVar2;
  char cVar4;
  byte bVar5;
  int iVar3;
  short sVar6;
  DfpStatue1State *state;
  int *piVar8;
  undefined8 extraout_f1;
  undefined8 uVar9;
  undefined8 extraout_f1_00;
  int local_28 [10];
  
  psVar1 = (short *)FUN_80286840();
  state = *(DfpStatue1State **)(psVar1 + 0x5c);
  if (((state->stateFlags >> 5 & 1) == 0) &&
     (uVar9 = extraout_f1, uVar2 = FUN_80017690((int)state->triggerSfxId), uVar2 == 0)) {
    if (state->effectPairCount == 4) {
      FUN_80006824(0,0x7e);
      state->stateFlags = state->stateFlags & 0xdf | 0x20;
      state->stateFlags = state->stateFlags & 0xef;
      state->stateFlags = state->stateFlags & 0xbf;
      FUN_80017698((int)state->triggerSfxId,1);
      FUN_80017698(0xedf,0);
      cVar4 = (**(code **)(*DAT_803dd72c + 0x40))((int)*(char *)(psVar1 + 0x56));
      if (cVar4 == '\x01') {
        FUN_80017698(0x9f7,1);
      }
      FUN_80006b4c();
    }
    else {
      if (((char)state->stateFlags < '\0') &&
         (state->stateFlags = state->stateFlags & 0x7f,
         ((u8)state->stateFlags >> 4 & 1) != 0)) {
        cVar4 = (**(code **)(*DAT_803dd72c + 0x40))((int)*(char *)(psVar1 + 0x56));
        if (cVar4 == '\x01') {
          FUN_80006b54(0x1d,0x96);
        }
        else {
          FUN_80006b54(0x1d,0xb4);
        }
        uVar9 = FUN_80006b50();
      }
      bVar5 = FUN_80006b44();
      if (bVar5 != 0) {
        piVar8 = gSfxplayerEffectHandles;
        for (sVar6 = 0; sVar6 < 4; sVar6 = sVar6 + 1) {
          if (*piVar8 != 0) {
            uVar9 = FUN_80017ac8(uVar9,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                                 *piVar8);
          }
          *piVar8 = 0;
          if (piVar8[1] != 0) {
            FUN_80017ac8(uVar9,param_2,param_3,param_4,param_5,param_6,param_7,param_8,piVar8[1]);
          }
          piVar8[1] = 0;
          uVar9 = FUN_80006824((uint)psVar1,0x1ce);
          piVar8 = piVar8 + 2;
        }
        state->effectPairCount = 0;
        state->stateFlags = state->stateFlags & 0xbf;
        state->stateFlags = state->stateFlags & 0xef;
        FUN_80017698(0xedf,0);
      }
      sfxplayer_updateEffectHandlePositions(psVar1);
      piVar8 = gSfxplayerEffectHandles;
      for (sVar6 = 0; sVar6 < 4; sVar6 = sVar6 + 1) {
        if (*piVar8 != 0) {
          local_28[0] = 0;
          iVar3 = ObjHits_GetPriorityHit(piVar8[1],local_28,(int *)0x0,(uint *)0x0);
          if (((short)iVar3 == 0x13) &&
             ((cVar4 = (**(code **)(*DAT_803dd72c + 0x40))((int)*(char *)(psVar1 + 0x56)),
              cVar4 == '\x01' || (*(int *)(local_28[0] + 0xf4) == (int)sVar6)))) {
            uVar9 = extraout_f1_00;
            if (*piVar8 != 0) {
              uVar9 = FUN_80017ac8(extraout_f1_00,param_2,param_3,param_4,param_5,param_6,param_7,
                                   param_8,*piVar8);
            }
            *piVar8 = 0;
            if (piVar8[1] != 0) {
              FUN_80017ac8(uVar9,param_2,param_3,param_4,param_5,param_6,param_7,param_8,piVar8[1]);
            }
            piVar8[1] = 0;
            FUN_80006824(0,0x409);
            state->effectPairCount = state->effectPairCount + 1;
          }
        }
        piVar8 = piVar8 + 2;
      }
    }
  }
  FUN_8028688c();
  return;
}


/* Trivial 4b 0-arg blr leaves. */
void dfpstatue1_free(void) {}
void dfpstatue1_render(void) {}
void dfpstatue1_hitDetect(void) {}
void dfpstatue1_release(void) {}
void dfpstatue1_initialise(void) {}
void dfperchwitch_free(void) {}
void dfperchwitch_render(void) {}
void dfperchwitch_hitDetect(void) {}
void dfperchwitch_release(void) {}
void dfperchwitch_initialise(void) {}

/* 8b "li r3, N; blr" returners. */
int dfpstatue1_getExtraSize(void) { return 0xa; }
int fn_802083B0(void) { return 0x0; }
int dfperchwitch_getExtraSize(void) { return 0x0; }
int fn_80208494(void) { return 0x0; }

/* plain forwarder.  Logic-only (~55%): existing dfpstatue1_updateState
 * signature has 8 args, but expected `bl` calls it with no setup. */
void dfpstatue1_update(void) { dfpstatue1_updateState(0,0.0,0.0,0,0,0,0,0); }
