#include "ghidra_import.h"
#include "main/dll/SH/SHthorntail.h"

extern undefined4 FUN_8000bb38();
extern uint FUN_80022150();
extern uint FUN_80022264();
extern undefined4 FUN_801d5470();
extern uint FUN_801d5558();
extern undefined4 FUN_80242fc0();

extern undefined4 DAT_803dc070;
extern undefined4* DAT_803dd6d8;
extern f64 DOUBLE_803e60c0;
extern f64 DOUBLE_803e60d8;
extern f32 FLOAT_803dc074;
extern f32 FLOAT_803e60b0;
extern f32 FLOAT_803e60c8;
extern f32 FLOAT_803e60cc;
extern f32 FLOAT_803e60d0;
extern char sSHthorntailSourceFile[];
extern char sThorntailEnteredInvalidState[];

/*
 * --INFO--
 *
 * Function: SHthorntail_updateState
 * EN v1.0 Address: TODO
 * EN v1.0 Size: TODO
 * EN v1.1 Address: 0x801D5764
 * EN v1.1 Size: 920b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void SHthorntail_updateState(undefined8 param_1,undefined8 param_2,undefined8 param_3,
                             undefined8 param_4,undefined8 param_5,undefined8 param_6,
                             undefined8 param_7,undefined8 param_8,short *param_9,int param_10,
                             undefined4 param_11,undefined4 param_12,undefined4 param_13,
                             undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
  int iVar1;
  uint uVar2;
  
  switch(*(undefined *)(param_10 + 0x624)) {
  case 0:
    uVar2 = FUN_80022150((double)FLOAT_803e60c8,(double)FLOAT_803e60cc,(float *)(param_10 + 0x910));
    if (uVar2 != 0) {
      FUN_8000bb38((uint)param_9,0x410);
    }
    *(float *)(param_10 + 0x630) = *(float *)(param_10 + 0x630) - FLOAT_803dc074;
    if (*(float *)(param_10 + 0x630) <= FLOAT_803e60d0) {
      *(undefined *)(param_10 + 0x624) = 1;
    }
    break;
  case 1:
    *(float *)(param_10 + 0x630) = *(float *)(param_10 + 0x630) - FLOAT_803dc074;
    if (*(float *)(param_10 + 0x630) <= FLOAT_803e60b0) {
      iVar1 = (**(code **)(*DAT_803dd6d8 + 0x24))(0);
      if (iVar1 == 0) {
        uVar2 = FUN_801d5558(param_9,param_10,*(int *)(param_9 + 0x26));
        *(char *)(param_10 + 0x624) = (char)uVar2;
      }
      else {
        *(undefined *)(param_10 + 0x624) = 0xb;
      }
    }
    break;
  case 2:
  case 3:
  case 4:
  case 5:
  case 6:
    if ((*(byte *)(param_10 + 0x625) & 1) != 0) {
      iVar1 = (**(code **)(*DAT_803dd6d8 + 0x24))(0);
      if (iVar1 == 0) {
        uVar2 = FUN_801d5558(param_9,param_10,*(int *)(param_9 + 0x26));
        *(char *)(param_10 + 0x624) = (char)uVar2;
      }
      else {
        *(undefined *)(param_10 + 0x624) = 0xb;
      }
    }
    break;
  case 7:
    if ((*(byte *)(param_10 + 0x625) & 1) != 0) {
      *(undefined *)(param_10 + 0x624) = 8;
      uVar2 = FUN_80022264(500,800);
      *(float *)(param_10 + 0x634) =
           (float)((double)CONCAT44(0x43300000,uVar2 ^ 0x80000000) - DOUBLE_803e60c0);
      uVar2 = FUN_80022264(1,3);
      *(char *)(param_10 + 0x63e) = (char)uVar2;
    }
    break;
  case 8:
    *(float *)(param_10 + 0x634) =
         *(float *)(param_10 + 0x634) -
         (float)((double)CONCAT44(0x43300000,(uint)DAT_803dc070) - DOUBLE_803e60d8);
    if (*(float *)(param_10 + 0x634) <= FLOAT_803e60b0) {
      if (*(char *)(param_10 + 0x63e) < '\x01') {
        *(undefined *)(param_10 + 0x624) = 10;
      }
      else {
        *(undefined *)(param_10 + 0x624) = 9;
      }
    }
    break;
  case 9:
    if ((*(byte *)(param_10 + 0x625) & 1) != 0) {
      *(undefined *)(param_10 + 0x624) = 8;
      uVar2 = FUN_80022264(500,800);
      *(float *)(param_10 + 0x634) =
           (float)((double)CONCAT44(0x43300000,uVar2 ^ 0x80000000) - DOUBLE_803e60c0);
      *(char *)(param_10 + 0x63e) = *(char *)(param_10 + 0x63e) + -1;
    }
    break;
  case 10:
    if ((*(byte *)(param_10 + 0x625) & 1) != 0) {
      *(undefined *)(param_10 + 0x624) = 0;
      uVar2 = FUN_80022264(1000,2000);
      *(float *)(param_10 + 0x630) =
           (float)((double)CONCAT44(0x43300000,uVar2 ^ 0x80000000) - DOUBLE_803e60c0);
    }
    break;
  case 0xb:
    if ((*(byte *)(param_10 + 0x625) & 1) != 0) {
      *(undefined *)(param_10 + 0x627) = 2;
      *(undefined *)(param_10 + 0x624) = 0xc;
    }
    break;
  case 0xc:
    FUN_801d5470((uint)param_9,param_10);
    if (((*(byte *)(param_10 + 0x625) & 1) != 0) &&
       (iVar1 = (**(code **)(*DAT_803dd6d8 + 0x24))(0), iVar1 == 0)) {
      *(undefined *)(param_10 + 0x624) = 0xd;
    }
    break;
  case 0xd:
    if ((*(byte *)(param_10 + 0x625) & 1) != 0) {
      *(undefined *)(param_10 + 0x624) = 0;
      uVar2 = FUN_80022264(1000,2000);
      *(float *)(param_10 + 0x630) =
           (float)((double)CONCAT44(0x43300000,uVar2 ^ 0x80000000) - DOUBLE_803e60c0);
    }
    break;
  default:
    FUN_80242fc0(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 sSHthorntailSourceFile,0x6cd,sThorntailEnteredInvalidState,param_12,param_13,
                 param_14,param_15,param_16);
  }
  return;
}
