// Function: FUN_801d7b8c
// Entry: 801d7b8c
// Size: 216 bytes

void FUN_801d7b8c(uint param_1)

{
  int iVar1;
  uint uVar2;
  int iVar3;
  undefined auStack_28 [12];
  float local_1c;
  undefined4 uStack_18;
  float local_14 [3];
  
  iVar3 = *(int *)(param_1 + 0xb8);
  iVar1 = FUN_80036868(param_1,(undefined4 *)0x0,(int *)0x0,(uint *)0x0,&local_1c,&uStack_18,
                       local_14);
  if (iVar1 != 0) {
    local_1c = local_1c + FLOAT_803dda58;
    local_14[0] = local_14[0] + FLOAT_803dda5c;
    FUN_8009a468(param_1,auStack_28,1,(int *)0x0);
    uVar2 = FUN_8008038c(3);
    if (uVar2 == 0) {
      FUN_8000bb38(param_1,700);
    }
    else {
      FUN_8000bb38(param_1,700);
    }
    FUN_800394f0(param_1,iVar3 + 0x14,0xab,-0x500,0xffffffff,0);
  }
  return;
}

