// Function: FUN_8014d29c
// Entry: 8014d29c
// Size: 404 bytes

void FUN_8014d29c(int param_1)

{
  uint uVar1;
  undefined4 uVar2;
  char in_r8;
  int iVar3;
  
  iVar3 = *(int *)(param_1 + 0xb8);
  if ((in_r8 != '\0') && (*(int *)(param_1 + 0xf4) == 0)) {
    FUN_8003b8f4((double)FLOAT_803e256c);
    uVar1 = *(uint *)(iVar3 + 0x2e8);
    if ((uVar1 & 3) != 0) {
      if ((uVar1 & 1) != 0) {
        *(uint *)(iVar3 + 0x2e8) = uVar1 & 0xfffffffe;
        *(uint *)(iVar3 + 0x2e8) = *(uint *)(iVar3 + 0x2e8) | 2;
      }
      if (*(int *)(iVar3 + 0x368) == 0) {
        uVar2 = FUN_8001f4c8(0,1);
        *(undefined4 *)(iVar3 + 0x368) = uVar2;
      }
      FUN_80099d84((double)FLOAT_803e256c,(double)*(float *)(iVar3 + 0x30c),param_1,3,
                   *(undefined4 *)(iVar3 + 0x368));
    }
    if ((*(uint *)(iVar3 + 0x2e8) & 4) != 0) {
      if (*(int *)(iVar3 + 0x368) == 0) {
        uVar2 = FUN_8001f4c8(0,1);
        *(undefined4 *)(iVar3 + 0x368) = uVar2;
      }
      FUN_80099d84((double)FLOAT_803e256c,(double)*(float *)(iVar3 + 0x30c),param_1,4,
                   *(undefined4 *)(iVar3 + 0x368));
    }
    if ((*(uint *)(iVar3 + 0x2e8) & 0x40) != 0) {
      FUN_8000da58(param_1,0x9e);
      FUN_80099d84((double)FLOAT_803e256c,(double)*(float *)(iVar3 + 0x30c),param_1,5,0);
    }
    if ((*(uint *)(iVar3 + 0x2e8) & 0x80) != 0) {
      FUN_8000da58(param_1,0x9e);
      FUN_80099d84((double)FLOAT_803e25f8,(double)*(float *)(iVar3 + 0x30c),param_1,6,0);
    }
    if ((*(uint *)(iVar3 + 0x2e8) & 0x100) != 0) {
      FUN_80099d84((double)FLOAT_803e25fc,(double)*(float *)(iVar3 + 0x30c),param_1,7,0);
    }
  }
  return;
}

