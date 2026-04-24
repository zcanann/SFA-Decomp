#include "ghidra_import.h"
#include "main/dll/crate.h"

extern undefined4 FUN_80006824();
extern undefined4 FUN_80006b4c();
extern undefined8 FUN_80017698();
extern undefined4 FUN_80017ac8();
extern undefined8 sfxplayer_update();
extern int gSfxplayerEffectHandles[8];
extern undefined4 sfxplayer_updateEffectHandlePositions();

/*
 * --INFO--
 *
 * Function: FUN_80208098
 * EN v1.0 Address: 0x80208098
 * EN v1.0 Size: 328b
 * EN v1.1 Address: 0x8020816C
 * EN v1.1 Size: 256b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_80208098(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,short *param_9,
            undefined4 param_10,int param_11)
{
  int iVar1;
  int iVar2;
  undefined8 uVar3;
  
  iVar2 = *(int *)(param_9 + 0x5c);
  *(byte *)(iVar2 + 8) = *(byte *)(iVar2 + 8) & 0x7f | 0x80;
  FUN_80006b4c();
  for (iVar1 = 0; iVar1 < (int)(uint)*(byte *)(param_11 + 0x8b); iVar1 = iVar1 + 1) {
    if (*(char *)(param_11 + iVar1 + 0x81) == '\x01') {
      *(byte *)(iVar2 + 8) = *(byte *)(iVar2 + 8) & 0xef | 0x10;
      *(undefined *)(iVar2 + 7) = 0;
      FUN_80017698((int)*(short *)(iVar2 + 2),0);
      uVar3 = FUN_80017698(0xedf,1);
      iVar1 = 0;
      do {
        uVar3 = sfxplayer_update(uVar3,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
        iVar1 = iVar1 + 1;
      } while (iVar1 < 4);
      *(byte *)(iVar2 + 8) = *(byte *)(iVar2 + 8) & 0xbf | 0x40;
    }
  }
  sfxplayer_updateEffectHandlePositions(param_9);
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
