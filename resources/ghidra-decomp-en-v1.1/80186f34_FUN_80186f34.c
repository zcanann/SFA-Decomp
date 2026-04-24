// Function: FUN_80186f34
// Entry: 80186f34
// Size: 256 bytes

void FUN_80186f34(int param_1)

{
  int iVar1;
  uint uVar2;
  int iVar3;
  double dVar4;
  
  iVar3 = *(int *)(param_1 + 0xb8);
  *(undefined4 *)(iVar3 + 4) = *(undefined4 *)(iVar3 + 8);
  *(undefined4 *)(iVar3 + 0x14) = *(undefined4 *)(iVar3 + 0x18);
  *(undefined4 *)(iVar3 + 0x24) = *(undefined4 *)(iVar3 + 0x28);
  *(undefined4 *)(iVar3 + 8) = *(undefined4 *)(iVar3 + 0xc);
  *(undefined4 *)(iVar3 + 0x18) = *(undefined4 *)(iVar3 + 0x1c);
  *(undefined4 *)(iVar3 + 0x28) = *(undefined4 *)(iVar3 + 0x2c);
  *(undefined4 *)(iVar3 + 0xc) = *(undefined4 *)(iVar3 + 0x10);
  *(undefined4 *)(iVar3 + 0x1c) = *(undefined4 *)(iVar3 + 0x20);
  *(undefined4 *)(iVar3 + 0x2c) = *(undefined4 *)(iVar3 + 0x30);
  if (*(byte *)(iVar3 + 0x70) >> 6 == 1) {
    iVar1 = FUN_8002bac4();
    dVar4 = (double)FUN_800217c8((float *)(param_1 + 0x18),(float *)(iVar1 + 0x18));
    *(float *)(iVar3 + 0x44) = (float)((double)FLOAT_803e475c * dVar4 + (double)FLOAT_803e4758);
  }
  else {
    uVar2 = FUN_80022264(0x3c,0x5a);
    *(float *)(iVar3 + 0x44) =
         FLOAT_803e475c * (float)((double)CONCAT44(0x43300000,uVar2 ^ 0x80000000) - DOUBLE_803e4748)
    ;
  }
  *(undefined4 *)(iVar3 + 0x10) = *(undefined4 *)(iVar3 + 0x34);
  *(undefined4 *)(iVar3 + 0x20) = *(undefined4 *)(iVar3 + 0x38);
  *(undefined4 *)(iVar3 + 0x30) = *(undefined4 *)(iVar3 + 0x3c);
  return;
}

