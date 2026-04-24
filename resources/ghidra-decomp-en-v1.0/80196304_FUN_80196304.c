// Function: FUN_80196304
// Entry: 80196304
// Size: 432 bytes

/* WARNING: Removing unreachable block (ram,0x80196484) */
/* WARNING: Removing unreachable block (ram,0x8019648c) */

void FUN_80196304(int param_1)

{
  int iVar1;
  int iVar2;
  int iVar3;
  undefined4 uVar4;
  undefined8 in_f30;
  double dVar5;
  undefined8 in_f31;
  double dVar6;
  float local_78;
  float local_74;
  undefined auStack112 [12];
  float local_64;
  float local_60;
  float local_5c;
  undefined4 local_58;
  uint uStack84;
  undefined4 local_50;
  uint uStack76;
  undefined4 local_48;
  uint uStack68;
  undefined4 local_40;
  uint uStack60;
  undefined4 local_38;
  uint uStack52;
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar4 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  __psq_st0(auStack24,(int)((ulonglong)in_f30 >> 0x20),0);
  __psq_st1(auStack24,(int)in_f30,0);
  iVar3 = *(int *)(param_1 + 0xb8);
  if ((*(byte *)(iVar3 + 2) & 1) == 0) {
    iVar2 = *(int *)(param_1 + 0x4c);
    iVar1 = FUN_8001ffb4((int)*(short *)(iVar2 + 0x34));
    if (iVar1 != 0) {
      FUN_800200e8((int)*(short *)(iVar2 + 0x32),1);
      *(byte *)(iVar3 + 2) = *(byte *)(iVar3 + 2) | 1;
      dVar6 = (double)FLOAT_803e4020;
      dVar5 = DOUBLE_803e4028;
      for (iVar3 = 0; iVar3 < (int)(uint)*(byte *)(iVar2 + 0x2c); iVar3 = iVar3 + 1) {
        uStack84 = FUN_800221a0((int)*(short *)(iVar2 + 0x2e),(int)*(short *)(iVar2 + 0x28));
        uStack84 = uStack84 ^ 0x80000000;
        local_58 = 0x43300000;
        local_78 = (float)(dVar6 * (double)(float)((double)CONCAT44(0x43300000,uStack84) - dVar5));
        uStack76 = FUN_800221a0((int)*(short *)(iVar2 + 0x30),(int)*(short *)(iVar2 + 0x2a));
        uStack76 = uStack76 ^ 0x80000000;
        local_50 = 0x43300000;
        local_74 = (float)(dVar6 * (double)(float)((double)CONCAT44(0x43300000,uStack76) - dVar5));
        uStack68 = FUN_800221a0((int)*(short *)(iVar2 + 0x18),(int)*(short *)(iVar2 + 0x1e));
        uStack68 = uStack68 ^ 0x80000000;
        local_48 = 0x43300000;
        local_64 = (float)((double)CONCAT44(0x43300000,uStack68) - dVar5);
        uStack60 = FUN_800221a0((int)*(short *)(iVar2 + 0x1a),(int)*(short *)(iVar2 + 0x20));
        uStack60 = uStack60 ^ 0x80000000;
        local_40 = 0x43300000;
        local_60 = (float)((double)CONCAT44(0x43300000,uStack60) - dVar5);
        uStack52 = FUN_800221a0((int)*(short *)(iVar2 + 0x1c),(int)*(short *)(iVar2 + 0x22));
        uStack52 = uStack52 ^ 0x80000000;
        local_38 = 0x43300000;
        local_5c = (float)((double)CONCAT44(0x43300000,uStack52) - dVar5);
        (**(code **)(*DAT_803dca88 + 8))
                  (param_1,(int)*(short *)(iVar2 + 0x24),auStack112,2,0xffffffff,&local_78);
      }
    }
  }
  __psq_l0(auStack8,uVar4);
  __psq_l1(auStack8,uVar4);
  __psq_l0(auStack24,uVar4);
  __psq_l1(auStack24,uVar4);
  return;
}

