// Function: FUN_8023695c
// Entry: 8023695c
// Size: 240 bytes

undefined4 FUN_8023695c(undefined4 param_1,int *param_2,int param_3)

{
  int iVar1;
  uint uVar2;
  undefined4 uVar3;
  undefined auStack_28 [28];
  
  uVar3 = 0;
  if ((*param_2 == 0) || (iVar1 = FUN_8001dc28(*param_2), iVar1 == 2)) {
    if (((int)*(short *)(param_3 + 0x24) == 0xffffffff) ||
       (uVar2 = FUN_80020078((int)*(short *)(param_3 + 0x24)), uVar2 != 0)) {
      if (((*(byte *)((int)param_2 + 0x22) & 4) == 0) ||
         (iVar1 = (**(code **)(*DAT_803dd6d8 + 0x24))(auStack_28), iVar1 != 0)) {
        if (*(char *)((int)param_2 + 0x26) == '\0') {
          param_2[5] = (int)(float)((double)CONCAT44(0x43300000,(uint)*(ushort *)(param_2 + 8)) -
                                   DOUBLE_803e7ff0);
          uVar3 = 1;
        }
      }
      else {
        uVar3 = 1;
      }
    }
    else {
      uVar3 = 1;
    }
  }
  else {
    uVar3 = 0;
  }
  return uVar3;
}

