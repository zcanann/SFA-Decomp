// Function: FUN_8016a660
// Entry: 8016a660
// Size: 408 bytes

void FUN_8016a660(int param_1)

{
  bool bVar1;
  char cVar6;
  int iVar2;
  undefined2 *puVar3;
  undefined2 uVar5;
  uint uVar4;
  int iVar7;
  int iVar8;
  
  iVar7 = *(int *)(param_1 + 0xb8);
  cVar6 = FUN_8002e04c();
  if (cVar6 != '\0') {
    iVar8 = 5;
    do {
      iVar2 = FUN_8002bdf4(0x24,0x482);
      *(undefined4 *)(iVar2 + 8) = *(undefined4 *)(param_1 + 0xc);
      *(undefined4 *)(iVar2 + 0xc) = *(undefined4 *)(param_1 + 0x10);
      *(undefined4 *)(iVar2 + 0x10) = *(undefined4 *)(param_1 + 0x14);
      *(undefined *)(iVar2 + 4) = 1;
      *(undefined *)(iVar2 + 5) = 1;
      *(undefined *)(iVar2 + 6) = 0xff;
      *(undefined *)(iVar2 + 7) = 0xff;
      puVar3 = (undefined2 *)FUN_8002df90(iVar2,5,0xffffffff,0xffffffff,0);
      if (puVar3 != (undefined2 *)0x0) {
        puVar3[1] = 0;
        uVar5 = FUN_800221a0(0,0xffff);
        *puVar3 = uVar5;
        uVar4 = FUN_800221a0(0xffffffce,0x32);
        *(float *)(puVar3 + 0x12) =
             FLOAT_803e3144 *
             (float)((double)CONCAT44(0x43300000,uVar4 ^ 0x80000000) - DOUBLE_803e3150) +
             *(float *)(param_1 + 0x24);
        uVar4 = FUN_800221a0(0xffffffce,0x32);
        *(float *)(puVar3 + 0x14) =
             FLOAT_803e3148 *
             (float)((double)CONCAT44(0x43300000,uVar4 ^ 0x80000000) - DOUBLE_803e3150) +
             *(float *)(param_1 + 0x28);
        uVar4 = FUN_800221a0(0xffffffce,0x32);
        *(float *)(puVar3 + 0x16) =
             FLOAT_803e3144 *
             (float)((double)CONCAT44(0x43300000,uVar4 ^ 0x80000000) - DOUBLE_803e3150) +
             *(float *)(param_1 + 0x2c);
        *(int *)(puVar3 + 0x62) = param_1;
      }
      bVar1 = iVar8 != 0;
      iVar8 = iVar8 + -1;
    } while (bVar1);
    *(undefined2 *)(iVar7 + 0x12) = 0x3c;
  }
  return;
}

