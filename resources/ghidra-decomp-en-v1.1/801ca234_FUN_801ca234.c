// Function: FUN_801ca234
// Entry: 801ca234
// Size: 356 bytes

void FUN_801ca234(uint param_1)

{
  short sVar1;
  uint uVar2;
  undefined4 uVar3;
  undefined4 *puVar4;
  
  puVar4 = *(undefined4 **)(param_1 + 0xb8);
  uVar2 = FUN_80020078(0x16a);
  if (uVar2 == 0) {
    *(undefined2 *)((int)puVar4 + 0x1e) = 0;
    *puVar4 = 0;
    FUN_800201ac(0x16c,0);
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
      uVar3 = (**(code **)(*DAT_803dd6d4 + 0x48))(0,param_1,0xffffffff);
      puVar4[6] = uVar3;
    }
    else if (sVar1 == 1) {
      if (DAT_803dcbd0 != '\0') {
        DAT_803dcbd0 = 0;
        FUN_8000bb38(param_1,0x1d4);
      }
      *(undefined2 *)((int)puVar4 + 0x1e) = 2;
      DAT_803dcbd0 = '\x01';
    }
    else if (sVar1 == 3) {
      *(uint *)(*(int *)(param_1 + 100) + 0x30) =
           *(uint *)(*(int *)(param_1 + 100) + 0x30) & 0xfffffffb;
      if (*(char *)(puVar4 + 8) < '\0') {
        FUN_800201ac(0x16b,1);
      }
      else {
        FUN_800201ac(0x16c,1);
      }
      FUN_8000b7dc(param_1,0x7f);
      *(byte *)(puVar4 + 8) = *(byte *)(puVar4 + 8) & 0xbf | 0x40;
    }
  }
  return;
}

