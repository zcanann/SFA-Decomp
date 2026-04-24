// Function: FUN_801d759c
// Entry: 801d759c
// Size: 216 bytes

void FUN_801d759c(int param_1)

{
  int iVar1;
  int iVar2;
  undefined auStack40 [12];
  float local_1c;
  undefined auStack24 [4];
  float local_14 [3];
  
  iVar2 = *(int *)(param_1 + 0xb8);
  iVar1 = FUN_80036770(param_1,0,0,0,&local_1c,auStack24,local_14);
  if (iVar1 != 0) {
    local_1c = local_1c + FLOAT_803dcdd8;
    local_14[0] = local_14[0] + FLOAT_803dcddc;
    FUN_8009a1dc((double)FLOAT_803e54a0,param_1,auStack40,1,0);
    iVar1 = FUN_80080100(3);
    if (iVar1 == 0) {
      FUN_8000bb18(param_1,700);
    }
    else {
      FUN_8000bb18(param_1,700);
    }
    FUN_800393f8(param_1,iVar2 + 0x14,0xab,0xfffffb00,0xffffffff,0);
  }
  return;
}

