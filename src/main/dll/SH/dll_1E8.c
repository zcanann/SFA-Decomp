#include "ghidra_import.h"
#include "main/dll/SH/dll_1E8.h"

extern undefined4 FUN_80006824();
extern double FUN_80017708();
extern int FUN_80017730();
extern uint FUN_80017760();
extern int FUN_80017a98();
extern int FUN_800575b4();
extern undefined4 FUN_800723a0();

extern f64 DOUBLE_803e60c0;
extern f32 FLOAT_803dc074;
extern f32 FLOAT_803e60b0;
extern f32 FLOAT_803e60b4;
extern f32 FLOAT_803e60b8;
extern f32 FLOAT_803e60bc;

/*
 * --INFO--
 *
 * Function: FUN_801d5174
 * EN v1.0 Address: 0x801D5174
 * EN v1.0 Size: 216b
 * EN v1.1 Address: 0x801D5470
 * EN v1.1 Size: 232b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801d5174(uint param_1,int param_2)
{
  byte bVar1;
  
  bVar1 = *(byte *)(param_2 + 0x627);
  if (bVar1 == 1) {
    *(float *)(param_2 + 0x628) = *(float *)(param_2 + 0x628) - FLOAT_803dc074;
    if (*(float *)(param_2 + 0x628) <= FLOAT_803e60b0) {
      FUN_80006824(param_1,0xa8);
      *(undefined *)(param_2 + 0x627) = 2;
    }
  }
  else if (bVar1 == 0) {
    *(float *)(param_2 + 0x628) = *(float *)(param_2 + 0x628) - FLOAT_803dc074;
    if (*(float *)(param_2 + 0x628) <= FLOAT_803e60b0) {
      FUN_80006824(param_1,0xa9);
      *(undefined *)(param_2 + 0x627) = 1;
      *(float *)(param_2 + 0x628) = FLOAT_803e60b4;
    }
  }
  else if ((bVar1 < 3) && ((*(byte *)(param_2 + 0x625) & 1) != 0)) {
    *(undefined *)(param_2 + 0x627) = 0;
    *(float *)(param_2 + 0x628) = FLOAT_803e60b8;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801d524c
 * EN v1.0 Address: 0x801D524C
 * EN v1.0 Size: 452b
 * EN v1.1 Address: 0x801D5558
 * EN v1.1 Size: 524b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
uint FUN_801d524c(short *param_1,int param_2,int param_3)
{
  short sVar1;
  int iVar2;
  uint uVar3;
  double dVar4;
  
  if (*(char *)(param_3 + 0x1b) == '\0') {
    uVar3 = 7;
  }
  else {
    iVar2 = FUN_80017a98();
    dVar4 = FUN_80017708((float *)(param_1 + 0xc),(float *)(iVar2 + 0x18));
    if ((double)FLOAT_803e60bc <= dVar4) {
      dVar4 = FUN_80017708((float *)(param_1 + 0xc),(float *)(param_3 + 8));
      if ((double)(float)((double)CONCAT44(0x43300000,
                                           (uint)*(byte *)(param_3 + 0x1b) *
                                           (uint)*(byte *)(param_3 + 0x1b) ^ 0x80000000) -
                         DOUBLE_803e60c0) < dVar4) {
        iVar2 = FUN_80017730();
        sVar1 = (short)iVar2 - *param_1;
        if (0x8000 < sVar1) {
          sVar1 = sVar1 + 1;
        }
        if (sVar1 < -0x8000) {
          sVar1 = sVar1 + -1;
        }
        iVar2 = (int)sVar1;
        if (iVar2 < 0) {
          iVar2 = -iVar2;
        }
        if (0x20 < iVar2) {
          FUN_80017730();
          FUN_800723a0();
          if (('\x01' < *(char *)(param_2 + 0x624)) && (*(char *)(param_2 + 0x624) < '\x06')) {
            return 6;
          }
          return 7;
        }
      }
      iVar2 = FUN_800575b4((double)(*(float *)(param_1 + 0x54) * *(float *)(param_1 + 4)),
                           (float *)(param_1 + 6));
      if (iVar2 == 0) {
        uVar3 = 7;
      }
      else if ((*(char *)(param_2 + 0x624) < '\x02') || ('\x05' < *(char *)(param_2 + 0x624))) {
        uVar3 = 2;
      }
      else {
        uVar3 = FUN_80017760(3,5);
        uVar3 = uVar3 & 0xff;
      }
    }
    else if ((*(char *)(param_2 + 0x624) < '\x02') || ('\x05' < *(char *)(param_2 + 0x624))) {
      uVar3 = 7;
    }
    else {
      uVar3 = 6;
    }
  }
  return uVar3;
}
