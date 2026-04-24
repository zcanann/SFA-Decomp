// Function: FUN_8002b050
// Entry: 8002b050
// Size: 328 bytes

void FUN_8002b050(int param_1,undefined2 param_2)

{
  short sVar1;
  byte bVar2;
  undefined auStack88 [76];
  
  bVar2 = 10;
  sVar1 = *(short *)(param_1 + 0x44);
  if (((sVar1 == 0x1c) || (sVar1 == 0x6d)) || (sVar1 == 0x2a)) {
    bVar2 = 0x28;
  }
  if ((*(byte *)(*(int *)(param_1 + 0x50) + 0x76) & 1) != 0) {
    if (*(byte *)(param_1 + 0xf0) < bVar2) {
      *(byte *)(param_1 + 0xf0) = *(byte *)(param_1 + 0xf0) + 1;
      FUN_8002ac30(param_1,0x1e,0xa0,0xff,0xff,0);
    }
    if (*(byte *)(param_1 + 0xf0) == bVar2) {
      if ((*(byte *)(param_1 + 0xe5) & 2) != 0) {
        FUN_8002a814(param_1);
      }
      *(undefined2 *)(param_1 + 0xe6) = param_2;
      *(byte *)(param_1 + 0xe5) = *(byte *)(param_1 + 0xe5) | 1;
      FUN_8002b47c(param_1,auStack88,0);
      FUN_80028488((double)(*(float *)(param_1 + 0xa8) * *(float *)(param_1 + 8)),param_1,
                   *(undefined4 *)(*(int *)(param_1 + 0x7c) + *(char *)(param_1 + 0xad) * 4),
                   auStack88,1);
      (**(code **)(*DAT_803dcab4 + 0xc))(param_1,0x7fc,0,100,0);
    }
  }
  return;
}

