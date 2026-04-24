// Function: FUN_801e6cdc
// Entry: 801e6cdc
// Size: 208 bytes

int FUN_801e6cdc(int param_1,int param_2)

{
  uint uVar1;
  int iVar2;
  short *psVar3;
  int local_18;
  float local_14 [3];
  
  iVar2 = *(int *)(param_1 + 0xb8);
  local_14[0] = FLOAT_803e6670;
  if ((*(char *)(param_2 + 0x27a) != '\0') && ((*(ushort *)(param_1 + 0xb0) & 0x800) != 0)) {
    (**(code **)(*DAT_803dd734 + 0xc))(param_1,0x7ef,local_14,0x50,0);
  }
  *(undefined *)(iVar2 + 0x9d6) = 0;
  *(float *)(param_2 + 0x280) = FLOAT_803e6674;
  if (*(char *)(iVar2 + 0x9d6) == '\0') {
    psVar3 = *(short **)(iVar2 + 0x9b0);
    local_18 = 0;
    uVar1 = FUN_800138d4(psVar3);
    if (uVar1 == 0) {
      FUN_80013900(psVar3,(uint)&local_18);
    }
    local_18 = local_18 + 1;
  }
  else {
    local_18 = 0;
  }
  return local_18;
}

