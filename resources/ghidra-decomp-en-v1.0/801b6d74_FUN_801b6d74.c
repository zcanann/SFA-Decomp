// Function: FUN_801b6d74
// Entry: 801b6d74
// Size: 848 bytes

/* WARNING: Removing unreachable block (ram,0x801b7098) */
/* WARNING: Removing unreachable block (ram,0x801b7090) */
/* WARNING: Removing unreachable block (ram,0x801b70a0) */

void FUN_801b6d74(int param_1)

{
  char cVar1;
  int iVar2;
  short *psVar3;
  undefined4 uVar4;
  undefined8 in_f29;
  double dVar5;
  undefined8 in_f30;
  double dVar6;
  undefined8 in_f31;
  double dVar7;
  undefined auStack120 [8];
  float local_70;
  float local_6c;
  float local_68;
  float local_64;
  undefined4 local_60;
  uint uStack92;
  undefined4 local_58;
  uint uStack84;
  undefined4 local_50;
  uint uStack76;
  undefined auStack40 [16];
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar4 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  __psq_st0(auStack24,(int)((ulonglong)in_f30 >> 0x20),0);
  __psq_st1(auStack24,(int)in_f30,0);
  __psq_st0(auStack40,(int)((ulonglong)in_f29 >> 0x20),0);
  __psq_st1(auStack40,(int)in_f29,0);
  psVar3 = *(short **)(param_1 + 0xb8);
  *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 8;
  cVar1 = *(char *)((int)psVar3 + 3);
  if (cVar1 == '\x01') {
    *(float *)(psVar3 + 2) = *(float *)(psVar3 + 2) + FLOAT_803db414;
    if (FLOAT_803e4a44 < *(float *)(psVar3 + 2)) {
      *(undefined *)((int)psVar3 + 3) = 2;
      FUN_8000bb18(0,0x109);
      FUN_8000bb18(param_1,0x47b);
      iVar2 = 0x1e;
      dVar6 = (double)FLOAT_803e4a48;
      dVar7 = (double)FLOAT_803e4a4c;
      dVar5 = DOUBLE_803e4a50;
      do {
        uStack92 = FUN_800221a0(0xffffff9c,100);
        uStack92 = uStack92 ^ 0x80000000;
        local_60 = 0x43300000;
        local_6c = (float)(dVar6 * (double)(float)((double)CONCAT44(0x43300000,uStack92) - dVar5));
        uStack84 = FUN_800221a0(0,0x15e);
        uStack84 = uStack84 ^ 0x80000000;
        local_58 = 0x43300000;
        local_68 = (float)(dVar6 * (double)(float)((double)CONCAT44(0x43300000,uStack84) - dVar5));
        uStack76 = FUN_800221a0(0xffffff9c,100);
        uStack76 = uStack76 ^ 0x80000000;
        local_50 = 0x43300000;
        local_64 = (float)(dVar6 * (double)(float)((double)CONCAT44(0x43300000,uStack76) - dVar5));
        local_70 = (float)dVar7;
        (**(code **)(*DAT_803dca88 + 8))(param_1,0x7fb,auStack120,2,0xffffffff,0);
        (**(code **)(*DAT_803dca88 + 8))(param_1,0x7fc,auStack120,2,0xffffffff,0);
        iVar2 = iVar2 + -1;
      } while (iVar2 != 0);
    }
    uStack76 = FUN_800221a0(0xffffff9c,100);
    uStack76 = uStack76 ^ 0x80000000;
    local_50 = 0x43300000;
    local_6c = FLOAT_803e4a48 * (float)((double)CONCAT44(0x43300000,uStack76) - DOUBLE_803e4a50);
    uStack84 = FUN_800221a0(0,0x15e);
    uStack84 = uStack84 ^ 0x80000000;
    local_58 = 0x43300000;
    local_68 = FLOAT_803e4a48 * (float)((double)CONCAT44(0x43300000,uStack84) - DOUBLE_803e4a50);
    uStack92 = FUN_800221a0(0xffffff9c,100);
    uStack92 = uStack92 ^ 0x80000000;
    local_60 = 0x43300000;
    local_64 = FLOAT_803e4a48 * (float)((double)CONCAT44(0x43300000,uStack92) - DOUBLE_803e4a50);
    local_70 = FLOAT_803e4a4c;
    (**(code **)(*DAT_803dca88 + 8))(param_1,0x7fc,auStack120,2,0xffffffff,0);
  }
  else if (cVar1 < '\x01') {
    if (-1 < cVar1) {
      if (*(char *)(psVar3 + 1) < '\x01') {
        if (*psVar3 != -1) {
          FUN_800200e8((int)*psVar3,1);
          FUN_80035f00(param_1);
          *(undefined *)((int)psVar3 + 3) = 1;
          *(float *)(psVar3 + 2) = FLOAT_803e4a40;
        }
      }
      else {
        iVar2 = FUN_8002b9ac();
        if (iVar2 != 0) {
          if ((*(byte *)(param_1 + 0xaf) & 4) != 0) {
            (**(code **)(**(int **)(iVar2 + 0x68) + 0x28))(iVar2,param_1,1,4);
          }
          *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) & 0xf7;
        }
      }
    }
  }
  else if (cVar1 < '\x03') {
    *(ushort *)(param_1 + 6) = *(ushort *)(param_1 + 6) | 0x4000;
  }
  __psq_l0(auStack8,uVar4);
  __psq_l1(auStack8,uVar4);
  __psq_l0(auStack24,uVar4);
  __psq_l1(auStack24,uVar4);
  __psq_l0(auStack40,uVar4);
  __psq_l1(auStack40,uVar4);
  return;
}

