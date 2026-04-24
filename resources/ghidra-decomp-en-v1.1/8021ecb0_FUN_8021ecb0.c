// Function: FUN_8021ecb0
// Entry: 8021ecb0
// Size: 220 bytes

void FUN_8021ecb0(short *param_1,int param_2,int *param_3)

{
  int iVar1;
  undefined2 auStack_28 [6];
  undefined4 local_1c;
  undefined4 local_18;
  undefined4 local_14;
  
  if (param_2 == 3) {
    *param_3 = 1;
  }
  else if (param_2 < 3) {
    if (1 < param_2) {
      iVar1 = FUN_80114420(0x11,auStack_28);
      if (iVar1 == 0) {
        *param_3 = *param_1 + 0x4000;
      }
      else {
        iVar1 = FUN_80021884();
        *param_3 = (int)(short)iVar1 + (int)DAT_803dcf90;
        iVar1 = *(int *)(param_1 + 0x5c);
        *(undefined4 *)(iVar1 + 0xc1c) = local_1c;
        *(undefined4 *)(iVar1 + 0xc20) = local_18;
        *(undefined4 *)(iVar1 + 0xc24) = local_14;
      }
    }
  }
  else if (param_2 < 5) {
    *param_3 = 0;
  }
  return;
}

