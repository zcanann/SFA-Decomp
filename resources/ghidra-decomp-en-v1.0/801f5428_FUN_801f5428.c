// Function: FUN_801f5428
// Entry: 801f5428
// Size: 468 bytes

/* WARNING: Removing unreachable block (ram,0x801f55d4) */

void FUN_801f5428(int param_1)

{
  int iVar1;
  undefined4 uVar2;
  int iVar3;
  undefined4 *puVar4;
  undefined4 uVar5;
  undefined8 in_f31;
  double dVar6;
  int local_38 [2];
  undefined4 local_30;
  uint uStack44;
  undefined auStack8 [8];
  
  uVar5 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  puVar4 = *(undefined4 **)(param_1 + 0xb8);
  iVar3 = *(int *)(param_1 + 0x4c);
  dVar6 = (double)FLOAT_803e5ea8;
  while (iVar1 = FUN_800374ec(param_1,local_38,0,0), iVar1 != 0) {
    if (local_38[0] == 0x7000b) {
      *(ushort *)(param_1 + 6) = *(ushort *)(param_1 + 6) | 0x4000;
      *(float *)(*(int *)(param_1 + 0xb8) + 0x70) = (float)dVar6;
      FUN_8001ff3c(0x13d);
      FUN_8001ff3c(0x5d6);
      FUN_8000bb18(param_1,0x49);
    }
  }
  if (*(char *)(puVar4 + 0x1b) < '\0') {
    iVar3 = FUN_800801a8(puVar4 + 0x1d);
    if (iVar3 != 0) {
      puVar4[0x1c] = FLOAT_803e5ea8;
    }
    if ((float)puVar4[0x1c] <= FLOAT_803e5ec4) {
      FUN_801f4f88(param_1);
    }
    else {
      puVar4[0x1c] = (float)puVar4[0x1c] - FLOAT_803db414;
      uStack44 = (int)DAT_803dc128 ^ 0x80000000;
      local_30 = 0x43300000;
      if ((float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803e5ed0) < (float)puVar4[0x1c]) {
        FUN_800999b4((double)FLOAT_803e5edc,param_1,4,5);
      }
      if ((float)puVar4[0x1c] <= FLOAT_803e5ec4) {
        FUN_8002cbc4(param_1);
      }
    }
  }
  else {
    iVar1 = 0;
    if ((*(short *)(iVar3 + 0x20) == -1) || (iVar3 = FUN_8001ffb4(), iVar3 != 0)) {
      iVar1 = 1;
    }
    *(byte *)(puVar4 + 0x1b) = (byte)(iVar1 << 7) | *(byte *)(puVar4 + 0x1b) & 0x7f;
    if (*(char *)(puVar4 + 0x1b) < '\0') {
      uVar2 = FUN_8001cc9c(param_1,100,0xff,100,0);
      *puVar4 = uVar2;
    }
  }
  __psq_l0(auStack8,uVar5);
  __psq_l1(auStack8,uVar5);
  return;
}

