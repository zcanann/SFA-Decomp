// Function: FUN_8016aca4
// Entry: 8016aca4
// Size: 224 bytes

void FUN_8016aca4(int param_1)

{
  uint uVar1;
  int iVar2;
  undefined2 *puVar3;
  
  puVar3 = *(undefined2 **)(param_1 + 0xb8);
  uVar1 = FUN_80022264(0xffff8000,0x7fff);
  *puVar3 = (short)uVar1;
  uVar1 = FUN_80022264(4000,5000);
  *(float *)(puVar3 + 6) =
       FLOAT_803e3de0 * (float)((double)CONCAT44(0x43300000,uVar1 ^ 0x80000000) - DOUBLE_803e3de8);
  uVar1 = FUN_80022264(0xffff8000,0x7fff);
  puVar3[2] = (short)uVar1;
  *(float *)(puVar3 + 4) = FLOAT_803e3dd4;
  uVar1 = FUN_80022264(0xe6,500);
  puVar3[3] = (short)uVar1;
  puVar3[8] = 0;
  puVar3[9] = 0;
  *(undefined *)(param_1 + 0x36) = 0xff;
  FUN_80035ff8(param_1);
  iVar2 = *(int *)(param_1 + 100);
  if (iVar2 != 0) {
    *(uint *)(iVar2 + 0x30) = *(uint *)(iVar2 + 0x30) | 0x810;
  }
  return;
}

