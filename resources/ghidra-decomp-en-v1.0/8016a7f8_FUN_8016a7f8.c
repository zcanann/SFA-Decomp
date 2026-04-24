// Function: FUN_8016a7f8
// Entry: 8016a7f8
// Size: 224 bytes

void FUN_8016a7f8(int param_1)

{
  undefined2 uVar3;
  uint uVar1;
  int iVar2;
  undefined2 *puVar4;
  
  puVar4 = *(undefined2 **)(param_1 + 0xb8);
  uVar3 = FUN_800221a0(0xffff8000,0x7fff);
  *puVar4 = uVar3;
  uVar1 = FUN_800221a0(4000,5000);
  *(float *)(puVar4 + 6) =
       FLOAT_803e3148 * (float)((double)CONCAT44(0x43300000,uVar1 ^ 0x80000000) - DOUBLE_803e3150);
  uVar3 = FUN_800221a0(0xffff8000,0x7fff);
  puVar4[2] = uVar3;
  *(float *)(puVar4 + 4) = FLOAT_803e313c;
  uVar3 = FUN_800221a0(0xe6,500);
  puVar4[3] = uVar3;
  puVar4[8] = 0;
  puVar4[9] = 0;
  *(undefined *)(param_1 + 0x36) = 0xff;
  FUN_80035f00(param_1);
  iVar2 = *(int *)(param_1 + 100);
  if (iVar2 != 0) {
    *(uint *)(iVar2 + 0x30) = *(uint *)(iVar2 + 0x30) | 0x810;
  }
  return;
}

