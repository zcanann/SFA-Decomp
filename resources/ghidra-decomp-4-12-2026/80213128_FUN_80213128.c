// Function: FUN_80213128
// Entry: 80213128
// Size: 360 bytes

undefined4 FUN_80213128(uint param_1,int param_2)

{
  uint uVar1;
  undefined4 uVar2;
  int iVar3;
  undefined4 local_18;
  undefined4 local_14 [2];
  
  iVar3 = *(int *)(param_1 + 0x4c);
  if (*(char *)(param_2 + 0x27b) != '\0') {
    (**(code **)(*DAT_803dd70c + 0x14))(param_1,param_2,1);
    *(undefined *)(DAT_803de9d4 + 0x3f) = 1;
    *(float *)(param_2 + 0x294) =
         *(float *)(iVar3 + (uint)*(byte *)(DAT_803de9d4 + 0x3f) * 4 + 0x38) / FLOAT_803e745c;
  }
  uVar1 = FUN_80022150((double)FLOAT_803e7460,(double)FLOAT_803e7464,(float *)(DAT_803de9d4 + 100));
  if (uVar1 != 0) {
    FUN_8000bb38(param_1,0x8f);
  }
  iVar3 = FUN_80215214(param_2);
  if (iVar3 == 0) {
    iVar3 = FUN_802153b4(param_1);
    if (iVar3 == 0) {
      uVar2 = 0;
    }
    else {
      uVar2 = 8;
    }
  }
  else {
    *(char *)((int)DAT_803de9d4 + 0x103) = *(char *)((int)DAT_803de9d4 + 0x103) + -1;
    if (*(char *)((int)DAT_803de9d4 + 0x103) < '\x01') {
      local_14[0] = 2;
      uVar1 = FUN_800138e4((short *)*DAT_803de9d4);
      if (uVar1 == 0) {
        FUN_80013978((short *)*DAT_803de9d4,(uint)local_14);
      }
    }
    else {
      local_18 = 5;
      uVar1 = FUN_800138e4((short *)*DAT_803de9d4);
      if (uVar1 == 0) {
        FUN_80013978((short *)*DAT_803de9d4,(uint)&local_18);
      }
    }
    uVar2 = 4;
  }
  return uVar2;
}

