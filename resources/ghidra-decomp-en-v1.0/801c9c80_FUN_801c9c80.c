// Function: FUN_801c9c80
// Entry: 801c9c80
// Size: 356 bytes

void FUN_801c9c80(int param_1)

{
  short sVar1;
  int iVar2;
  undefined4 uVar3;
  undefined4 *puVar4;
  
  puVar4 = *(undefined4 **)(param_1 + 0xb8);
  iVar2 = FUN_8001ffb4(0x16a);
  if (iVar2 == 0) {
    *(undefined2 *)((int)puVar4 + 0x1e) = 0;
    *puVar4 = 0;
    FUN_800200e8(0x16c,0);
  }
  else {
    sVar1 = *(short *)((int)puVar4 + 0x1e);
    if (sVar1 == 0) {
      *(uint *)(*(int *)(param_1 + 100) + 0x30) =
           *(uint *)(*(int *)(param_1 + 100) + 0x30) & 0xfffffffb;
      *(undefined2 *)((int)puVar4 + 0x1e) = 1;
    }
    else if (sVar1 == 2) {
      *(undefined2 *)((int)puVar4 + 0x1e) = 3;
      uVar3 = (**(code **)(*DAT_803dca54 + 0x48))(0,param_1,0xffffffff);
      puVar4[6] = uVar3;
    }
    else if (sVar1 == 1) {
      if (DAT_803dbf68 != '\0') {
        DAT_803dbf68 = 0;
        FUN_8000bb18(param_1,0x1d4);
      }
      *(undefined2 *)((int)puVar4 + 0x1e) = 2;
      DAT_803dbf68 = '\x01';
    }
    else if (sVar1 == 3) {
      *(uint *)(*(int *)(param_1 + 100) + 0x30) =
           *(uint *)(*(int *)(param_1 + 100) + 0x30) & 0xfffffffb;
      if (*(char *)(puVar4 + 8) < '\0') {
        FUN_800200e8(0x16b,1);
      }
      else {
        FUN_800200e8(0x16c,1);
      }
      FUN_8000b7bc(param_1,0x7f);
      *(byte *)(puVar4 + 8) = *(byte *)(puVar4 + 8) & 0xbf | 0x40;
    }
  }
  return;
}

