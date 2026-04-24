// Function: FUN_801e66ec
// Entry: 801e66ec
// Size: 208 bytes

int FUN_801e66ec(int param_1,int param_2)

{
  int iVar1;
  undefined4 uVar2;
  int local_18;
  float local_14 [3];
  
  iVar1 = *(int *)(param_1 + 0xb8);
  local_14[0] = FLOAT_803e59d8;
  if ((*(char *)(param_2 + 0x27a) != '\0') && ((*(ushort *)(param_1 + 0xb0) & 0x800) != 0)) {
    (**(code **)(*DAT_803dcab4 + 0xc))(param_1,0x7ef,local_14,0x50,0);
  }
  *(undefined *)(iVar1 + 0x9d6) = 0;
  *(float *)(param_2 + 0x280) = FLOAT_803e59dc;
  if (*(char *)(iVar1 + 0x9d6) == '\0') {
    uVar2 = *(undefined4 *)(iVar1 + 0x9b0);
    local_18 = 0;
    iVar1 = FUN_800138b4(uVar2);
    if (iVar1 == 0) {
      FUN_800138e0(uVar2,&local_18);
    }
    local_18 = local_18 + 1;
  }
  else {
    local_18 = 0;
  }
  return local_18;
}

