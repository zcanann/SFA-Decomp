// Function: FUN_80236298
// Entry: 80236298
// Size: 240 bytes

undefined4 FUN_80236298(undefined4 param_1,int *param_2,int param_3)

{
  int iVar1;
  undefined4 uVar2;
  undefined auStack40 [28];
  
  uVar2 = 0;
  if ((*param_2 == 0) || (iVar1 = FUN_8001db64(), iVar1 == 2)) {
    if ((*(short *)(param_3 + 0x24) == -1) || (iVar1 = FUN_8001ffb4(), iVar1 != 0)) {
      if (((*(byte *)((int)param_2 + 0x22) & 4) == 0) ||
         (iVar1 = (**(code **)(*DAT_803dca58 + 0x24))(auStack40), iVar1 != 0)) {
        if (*(char *)((int)param_2 + 0x26) == '\0') {
          param_2[5] = (int)(float)((double)CONCAT44(0x43300000,(uint)*(ushort *)(param_2 + 8)) -
                                   DOUBLE_803e7358);
          uVar2 = 1;
        }
      }
      else {
        uVar2 = 1;
      }
    }
    else {
      uVar2 = 1;
    }
  }
  else {
    uVar2 = 0;
  }
  return uVar2;
}

