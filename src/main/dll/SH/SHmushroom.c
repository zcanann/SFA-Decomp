#include "ghidra_import.h"
#include "main/dll/SH/SHmushroom.h"

extern undefined4 FUN_800068c4();
extern u32 randomGetRange(int min, int max);
extern undefined4 ObjHits_RefreshObjectState();

extern undefined4* DAT_803dd708;
extern f64 DOUBLE_803e5ff8;
extern f32 FLOAT_803e5ff0;
extern f32 FLOAT_803e5ff4;

/*
 * --INFO--
 *
 * Function: bombplant_update
 * EN v1.0 Address: 0x801D2C54
 * EN v1.0 Size: 356b
 * EN v1.1 Address: 0x801D2E5C
 * EN v1.1 Size: 376b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 bombplant_update(uint param_1)
{
  uint uVar1;
  int iVar2;
  float *pfVar3;
  
  pfVar3 = *(float **)(param_1 + 0xb8);
  if (*(char *)(pfVar3 + 5) == '\0') {
    FUN_800068c4(param_1,0x3fd);
    iVar2 = *(int *)(param_1 + 0x4c);
    if ((*(byte *)((int)pfVar3 + 0x15) & 2) != 0) {
      *(byte *)((int)pfVar3 + 0x15) = *(byte *)((int)pfVar3 + 0x15) & 0xfd;
      uVar1 = randomGetRange(0xffffffce,0x32);
      *pfVar3 = (float)((double)CONCAT44(0x43300000,
                                         (int)*(short *)(iVar2 + 0x1a) + uVar1 ^ 0x80000000) -
                       DOUBLE_803e5ff8);
    }
    if ((*(ushort *)(param_1 + 0xb0) & 0x800) != 0) {
      (**(code **)(*DAT_803dd708 + 8))(param_1,0x7f1,0,2,0xffffffff,0);
    }
  }
  else {
    *(ushort *)(param_1 + 6) = *(ushort *)(param_1 + 6) & 0xbfff;
    iVar2 = *(int *)(param_1 + 0x4c);
    *(undefined *)(param_1 + 0x36) = 0xff;
    *(ushort *)(param_1 + 6) = *(ushort *)(param_1 + 6) & 0xbfff;
    *(undefined4 *)(param_1 + 0xc) = *(undefined4 *)(iVar2 + 8);
    *(undefined4 *)(param_1 + 0x10) = *(undefined4 *)(iVar2 + 0xc);
    *(undefined4 *)(param_1 + 0x14) = *(undefined4 *)(iVar2 + 0x10);
    *(float *)(param_1 + 8) = FLOAT_803e5ff0;
    pfVar3[2] = FLOAT_803e5ff4;
    pfVar3[1] = pfVar3[3];
    pfVar3[4] = pfVar3[1] / pfVar3[2];
    *pfVar3 = pfVar3[2];
    ObjHits_RefreshObjectState(param_1);
    *(undefined *)(pfVar3 + 5) = 0;
    *(byte *)((int)pfVar3 + 0x15) = *(byte *)((int)pfVar3 + 0x15) | 2;
  }
  return 0;
}
