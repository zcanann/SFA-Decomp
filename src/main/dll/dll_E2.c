#include "ghidra_import.h"
#include "main/dll/dll_E2.h"

extern uint FUN_80017690();
extern double FUN_80017714();
extern int ObjGroup_FindNearestObject();
extern int FUN_8005b024();

extern f32 lbl_803E30BC;
extern f32 lbl_803E3154;

/*
 * --INFO--
 *
 * Function: FUN_8013dc88
 * EN v1.0 Address: 0x8013DC88
 * EN v1.0 Size: 348b
 * EN v1.1 Address: 0x8013DEC4
 * EN v1.1 Size: 332b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined FUN_8013dc88(int param_1,int param_2)
{
  byte bVar1;
  int iVar2;
  uint uVar3;
  undefined uVar4;
  double dVar5;
  float local_18 [3];
  
  local_18[0] = lbl_803E30BC;
  bVar1 = *(byte *)(param_2 + 0x58) >> 1 & 0xf;
  uVar4 = bVar1 != 0;
  if ((bool)uVar4) {
    *(byte *)(param_2 + 0x58) = (bVar1 - 1) * '\x02' & 0x1e | *(byte *)(param_2 + 0x58) & 0xe1;
  }
  iVar2 = ObjGroup_FindNearestObject(0x53,param_1,local_18);
  if (iVar2 == 0) {
    if ((*(char *)(param_2 + 0xd) != '\x03') &&
       ((*(ushort *)(*(int *)(param_2 + 4) + 0xb0) & 0x1000) != 0)) {
      iVar2 = FUN_8005b024();
      if (iVar2 == 0x38) {
        uVar3 = FUN_80017690(0x385);
        if (((uVar3 == 0) && (uVar3 = FUN_80017690(900), uVar3 != 0)) &&
           ((uVar3 = FUN_80017690(0xc1), uVar3 != 0 || (uVar3 = FUN_80017690(0x12e), uVar3 != 0))))
        {
          uVar4 = true;
        }
      }
      else {
        *(byte *)(param_2 + 0x58) = *(byte *)(param_2 + 0x58) & 0xe1 | 0x1e;
        uVar4 = true;
      }
    }
    if (((bool)uVar4 == true) &&
       (dVar5 = FUN_80017714((float *)(*(int *)(param_2 + 4) + 0x18),(float *)(param_1 + 0x18)),
       dVar5 < (double)lbl_803E3154)) {
      uVar4 = 2;
    }
  }
  else {
    uVar4 = 0;
  }
  return uVar4;
}
