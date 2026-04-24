// Function: FUN_801fdb24
// Entry: 801fdb24
// Size: 384 bytes

void FUN_801fdb24(int param_1)

{
  uint uVar1;
  int iVar2;
  int iVar3;
  short *psVar4;
  float local_18 [3];
  
  psVar4 = *(short **)(param_1 + 0xb8);
  *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 8;
  if ((*(char *)((int)psVar4 + 5) < '\0') ||
     (((int)psVar4[1] != 0xffffffff && (uVar1 = FUN_80020078((int)psVar4[1]), uVar1 == 0)))) {
    uVar1 = FUN_80020078((int)*psVar4);
    *(byte *)((int)psVar4 + 5) = (byte)((uVar1 & 1) << 7) | *(byte *)((int)psVar4 + 5) & 0x7f;
    if ((uVar1 & 1) == 0) {
      *(char *)(psVar4 + 2) = (char)*(undefined2 *)(*(int *)(param_1 + 0x4c) + 0x1a);
    }
  }
  else if ((*(char *)(psVar4 + 2) < '\x01') && (-1 < *(char *)((int)psVar4 + 5))) {
    if ((int)*psVar4 != 0xffffffff) {
      FUN_800201ac((int)*psVar4,1);
      *(byte *)((int)psVar4 + 5) = *(byte *)((int)psVar4 + 5) & 0x7f | 0x80;
    }
  }
  else {
    iVar2 = FUN_8002ba84();
    if ((iVar2 != 0) &&
       ((local_18[0] = FLOAT_803e6df0, (*(byte *)((int)psVar4 + 5) >> 6 & 1) != 0 ||
        (iVar3 = FUN_80036f50(5,param_1,local_18), iVar3 == 0)))) {
      if ((*(byte *)(param_1 + 0xaf) & 4) != 0) {
        (**(code **)(**(int **)(iVar2 + 0x68) + 0x28))(iVar2,param_1,1,4);
      }
      *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) & 0xf7;
      FUN_80041110();
    }
  }
  return;
}

