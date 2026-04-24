#include "ghidra_import.h"
#include "main/dll/crate2.h"

extern undefined8 FUN_8000bb38();
extern byte FUN_8001469c();
extern undefined4 FUN_800146a8();
extern undefined8 FUN_800146c8();
extern undefined4 FUN_800146e8();
extern uint FUN_80020078();
extern undefined4 FUN_800201ac();
extern undefined8 FUN_8002cc9c();
extern int FUN_80036974();
extern undefined4 FUN_80207cc4();
extern undefined4 FUN_80286840();
extern undefined4 FUN_8028688c();

extern int DAT_803add98;
extern undefined4* DAT_803dd72c;

/*
 * --INFO--
 *
 * Function: FUN_8020831c
 * EN v1.0 Address: TODO
 * EN v1.0 Size: TODO
 * EN v1.1 Address: 0x8020831C
 * EN v1.1 Size: 728b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020831c(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
  short *psVar1;
  uint uVar2;
  char cVar4;
  byte bVar5;
  int iVar3;
  short sVar6;
  short *psVar7;
  int *piVar8;
  undefined8 extraout_f1;
  undefined8 uVar9;
  undefined8 extraout_f1_00;
  int local_28 [10];
  
  psVar1 = (short *)FUN_80286840();
  psVar7 = *(short **)(psVar1 + 0x5c);
  if (((*(byte *)(psVar7 + 4) >> 5 & 1) == 0) &&
     (uVar9 = extraout_f1, uVar2 = FUN_80020078((int)*psVar7), uVar2 == 0)) {
    if (*(char *)((int)psVar7 + 7) == '\x04') {
      FUN_8000bb38(0,0x7e);
      *(byte *)(psVar7 + 4) = *(byte *)(psVar7 + 4) & 0xdf | 0x20;
      *(byte *)(psVar7 + 4) = *(byte *)(psVar7 + 4) & 0xef;
      *(byte *)(psVar7 + 4) = *(byte *)(psVar7 + 4) & 0xbf;
      FUN_800201ac((int)*psVar7,1);
      FUN_800201ac(0xedf,0);
      cVar4 = (**(code **)(*DAT_803dd72c + 0x40))((int)*(char *)(psVar1 + 0x56));
      if (cVar4 == '\x01') {
        FUN_800201ac(0x9f7,1);
      }
      FUN_800146a8();
    }
    else {
      if (((char)*(byte *)(psVar7 + 4) < '\0') &&
         (*(byte *)(psVar7 + 4) = *(byte *)(psVar7 + 4) & 0x7f,
         (*(byte *)(psVar7 + 4) >> 4 & 1) != 0)) {
        cVar4 = (**(code **)(*DAT_803dd72c + 0x40))((int)*(char *)(psVar1 + 0x56));
        if (cVar4 == '\x01') {
          FUN_800146e8(0x1d,0x96);
        }
        else {
          FUN_800146e8(0x1d,0xb4);
        }
        uVar9 = FUN_800146c8();
      }
      bVar5 = FUN_8001469c();
      if (bVar5 != 0) {
        piVar8 = &DAT_803add98;
        for (sVar6 = 0; sVar6 < 4; sVar6 = sVar6 + 1) {
          if (*piVar8 != 0) {
            uVar9 = FUN_8002cc9c(uVar9,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                                 *piVar8);
          }
          *piVar8 = 0;
          if (piVar8[1] != 0) {
            FUN_8002cc9c(uVar9,param_2,param_3,param_4,param_5,param_6,param_7,param_8,piVar8[1]);
          }
          piVar8[1] = 0;
          uVar9 = FUN_8000bb38((uint)psVar1,0x1ce);
          piVar8 = piVar8 + 2;
        }
        *(undefined *)((int)psVar7 + 7) = 0;
        *(byte *)(psVar7 + 4) = *(byte *)(psVar7 + 4) & 0xbf;
        *(byte *)(psVar7 + 4) = *(byte *)(psVar7 + 4) & 0xef;
        FUN_800201ac(0xedf,0);
      }
      FUN_80207cc4(psVar1);
      piVar8 = &DAT_803add98;
      for (sVar6 = 0; sVar6 < 4; sVar6 = sVar6 + 1) {
        if (*piVar8 != 0) {
          local_28[0] = 0;
          iVar3 = FUN_80036974(piVar8[1],local_28,(int *)0x0,(uint *)0x0);
          if (((short)iVar3 == 0x13) &&
             ((cVar4 = (**(code **)(*DAT_803dd72c + 0x40))((int)*(char *)(psVar1 + 0x56)),
              cVar4 == '\x01' || (*(int *)(local_28[0] + 0xf4) == (int)sVar6)))) {
            uVar9 = extraout_f1_00;
            if (*piVar8 != 0) {
              uVar9 = FUN_8002cc9c(extraout_f1_00,param_2,param_3,param_4,param_5,param_6,param_7,
                                   param_8,*piVar8);
            }
            *piVar8 = 0;
            if (piVar8[1] != 0) {
              FUN_8002cc9c(uVar9,param_2,param_3,param_4,param_5,param_6,param_7,param_8,piVar8[1]);
            }
            piVar8[1] = 0;
            FUN_8000bb38(0,0x409);
            *(char *)((int)psVar7 + 7) = *(char *)((int)psVar7 + 7) + '\x01';
          }
        }
        piVar8 = piVar8 + 2;
      }
    }
  }
  FUN_8028688c();
  return;
}
