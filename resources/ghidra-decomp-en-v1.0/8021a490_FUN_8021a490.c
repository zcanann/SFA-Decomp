// Function: FUN_8021a490
// Entry: 8021a490
// Size: 328 bytes

void FUN_8021a490(int param_1)

{
  int iVar1;
  undefined4 *puVar2;
  
  puVar2 = *(undefined4 **)(param_1 + 0xb8);
  *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 8;
  if ((*(short *)(*(int *)(param_1 + 0x4c) + 0x20) == -1) || (iVar1 = FUN_8001ffb4(), iVar1 != 0)) {
    iVar1 = FUN_80080150(puVar2 + 4);
    if (iVar1 == 0) {
      if (*(char *)((int)puVar2 + 0x16) < '\x01') {
        *(undefined *)((int)puVar2 + 0x17) = 1;
        FUN_80080178(puVar2 + 4,(int)(float)puVar2[3]);
        FUN_800200e8((int)*(short *)(puVar2 + 5),1);
      }
      else {
        iVar1 = FUN_8002b9ac();
        if (iVar1 != 0) {
          if ((*(byte *)(param_1 + 0xaf) & 4) != 0) {
            (**(code **)(**(int **)(iVar1 + 0x68) + 0x28))(iVar1,param_1,1,4);
          }
          *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) & 0xf7;
          FUN_80041018(param_1);
        }
      }
    }
    iVar1 = FUN_800801a8(puVar2 + 4);
    if (iVar1 != 0) {
      *puVar2 = 0;
      puVar2[4] = FLOAT_803e69e4;
      *(undefined *)((int)puVar2 + 0x17) = 0;
      *(undefined *)((int)puVar2 + 0x16) = 1;
      FUN_800200e8((int)*(short *)(puVar2 + 5),0);
      FUN_800200e8(0xea4,0);
    }
  }
  return;
}

