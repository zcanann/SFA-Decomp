// Function: FUN_801fd4ec
// Entry: 801fd4ec
// Size: 384 bytes

void FUN_801fd4ec(int param_1)

{
  int iVar1;
  int iVar2;
  uint uVar3;
  short *psVar4;
  float local_18 [3];
  
  psVar4 = *(short **)(param_1 + 0xb8);
  *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 8;
  if ((*(char *)((int)psVar4 + 5) < '\0') ||
     ((psVar4[1] != -1 && (iVar1 = FUN_8001ffb4(), iVar1 == 0)))) {
    uVar3 = FUN_8001ffb4((int)*psVar4);
    *(byte *)((int)psVar4 + 5) = (byte)((uVar3 & 1) << 7) | *(byte *)((int)psVar4 + 5) & 0x7f;
    if ((uVar3 & 1) == 0) {
      *(char *)(psVar4 + 2) = (char)*(undefined2 *)(*(int *)(param_1 + 0x4c) + 0x1a);
    }
  }
  else if ((*(char *)(psVar4 + 2) < '\x01') && (-1 < *(char *)((int)psVar4 + 5))) {
    if (*psVar4 != -1) {
      FUN_800200e8((int)*psVar4,1);
      *(byte *)((int)psVar4 + 5) = *(byte *)((int)psVar4 + 5) & 0x7f | 0x80;
    }
  }
  else {
    iVar1 = FUN_8002b9ac();
    if ((iVar1 != 0) &&
       ((local_18[0] = FLOAT_803e6158, (*(byte *)((int)psVar4 + 5) >> 6 & 1) != 0 ||
        (iVar2 = FUN_80036e58(5,param_1,local_18), iVar2 == 0)))) {
      if ((*(byte *)(param_1 + 0xaf) & 4) != 0) {
        (**(code **)(**(int **)(iVar1 + 0x68) + 0x28))(iVar1,param_1,1,4);
      }
      *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) & 0xf7;
      FUN_80041018(param_1);
    }
  }
  return;
}

