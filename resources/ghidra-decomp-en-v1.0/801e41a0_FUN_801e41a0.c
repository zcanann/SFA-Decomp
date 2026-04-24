// Function: FUN_801e41a0
// Entry: 801e41a0
// Size: 224 bytes

void FUN_801e41a0(int param_1)

{
  undefined4 uVar1;
  int iVar2;
  
  iVar2 = *(int *)(param_1 + 0xb8);
  if (*(int *)(iVar2 + 0x20) == 0) {
    uVar1 = FUN_8001f4c8(param_1,1);
    *(undefined4 *)(iVar2 + 0x20) = uVar1;
    if (*(int *)(iVar2 + 0x20) != 0) {
      FUN_8001db2c(*(int *)(iVar2 + 0x20),2);
      FUN_8001daf0(*(undefined4 *)(iVar2 + 0x20),200,0x3c,0,0);
      FUN_8001db14(*(undefined4 *)(iVar2 + 0x20),1);
      FUN_8001dc38((double)FLOAT_803e58c8,(double)FLOAT_803e58cc,*(undefined4 *)(iVar2 + 0x20));
    }
  }
  *(ushort *)(*(int *)(param_1 + 0x54) + 0x60) =
       *(ushort *)(*(int *)(param_1 + 0x54) + 0x60) & 0xfffe;
  *(float *)(param_1 + 8) = *(float *)(param_1 + 8) * FLOAT_803e58d0;
  *(byte *)(iVar2 + 0x1a) = *(byte *)(iVar2 + 0x1a) | 2;
  FUN_8000bb18(param_1,0x35);
  FUN_8000bb18(param_1,0x2ca);
  return;
}

