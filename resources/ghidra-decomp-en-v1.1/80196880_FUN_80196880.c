// Function: FUN_80196880
// Entry: 80196880
// Size: 432 bytes

/* WARNING: Removing unreachable block (ram,0x80196a08) */
/* WARNING: Removing unreachable block (ram,0x80196a00) */
/* WARNING: Removing unreachable block (ram,0x80196898) */
/* WARNING: Removing unreachable block (ram,0x80196890) */

void FUN_80196880(int param_1)

{
  uint uVar1;
  int iVar2;
  int iVar3;
  double dVar4;
  double dVar5;
  float local_78;
  float local_74;
  undefined auStack_70 [12];
  float local_64;
  float local_60;
  float local_5c;
  undefined4 local_58;
  uint uStack_54;
  undefined4 local_50;
  uint uStack_4c;
  undefined4 local_48;
  uint uStack_44;
  undefined4 local_40;
  uint uStack_3c;
  undefined4 local_38;
  uint uStack_34;
  
  iVar3 = *(int *)(param_1 + 0xb8);
  if ((*(byte *)(iVar3 + 2) & 1) == 0) {
    iVar2 = *(int *)(param_1 + 0x4c);
    uVar1 = FUN_80020078((int)*(short *)(iVar2 + 0x34));
    if (uVar1 != 0) {
      FUN_800201ac((int)*(short *)(iVar2 + 0x32),1);
      *(byte *)(iVar3 + 2) = *(byte *)(iVar3 + 2) | 1;
      dVar5 = (double)FLOAT_803e4cb8;
      dVar4 = DOUBLE_803e4cc0;
      for (iVar3 = 0; iVar3 < (int)(uint)*(byte *)(iVar2 + 0x2c); iVar3 = iVar3 + 1) {
        uStack_54 = FUN_80022264((int)*(short *)(iVar2 + 0x2e),(int)*(short *)(iVar2 + 0x28));
        uStack_54 = uStack_54 ^ 0x80000000;
        local_58 = 0x43300000;
        local_78 = (float)(dVar5 * (double)(float)((double)CONCAT44(0x43300000,uStack_54) - dVar4));
        uStack_4c = FUN_80022264((int)*(short *)(iVar2 + 0x30),(int)*(short *)(iVar2 + 0x2a));
        uStack_4c = uStack_4c ^ 0x80000000;
        local_50 = 0x43300000;
        local_74 = (float)(dVar5 * (double)(float)((double)CONCAT44(0x43300000,uStack_4c) - dVar4));
        uStack_44 = FUN_80022264((int)*(short *)(iVar2 + 0x18),(int)*(short *)(iVar2 + 0x1e));
        uStack_44 = uStack_44 ^ 0x80000000;
        local_48 = 0x43300000;
        local_64 = (float)((double)CONCAT44(0x43300000,uStack_44) - dVar4);
        uStack_3c = FUN_80022264((int)*(short *)(iVar2 + 0x1a),(int)*(short *)(iVar2 + 0x20));
        uStack_3c = uStack_3c ^ 0x80000000;
        local_40 = 0x43300000;
        local_60 = (float)((double)CONCAT44(0x43300000,uStack_3c) - dVar4);
        uStack_34 = FUN_80022264((int)*(short *)(iVar2 + 0x1c),(int)*(short *)(iVar2 + 0x22));
        uStack_34 = uStack_34 ^ 0x80000000;
        local_38 = 0x43300000;
        local_5c = (float)((double)CONCAT44(0x43300000,uStack_34) - dVar4);
        (**(code **)(*DAT_803dd708 + 8))
                  (param_1,(int)*(short *)(iVar2 + 0x24),auStack_70,2,0xffffffff,&local_78);
      }
    }
  }
  return;
}

