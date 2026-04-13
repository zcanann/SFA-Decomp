// Function: FUN_802ab030
// Entry: 802ab030
// Size: 432 bytes

/* WARNING: Removing unreachable block (ram,0x802ab1bc) */
/* WARNING: Removing unreachable block (ram,0x802ab1b4) */
/* WARNING: Removing unreachable block (ram,0x802ab048) */
/* WARNING: Removing unreachable block (ram,0x802ab040) */

void FUN_802ab030(int param_1)

{
  uint uVar1;
  int iVar2;
  double dVar3;
  double dVar4;
  undefined auStack_58 [12];
  float local_4c;
  float local_48;
  float local_44;
  undefined4 local_40;
  uint uStack_3c;
  undefined4 local_38;
  uint uStack_34;
  
  local_48 = FLOAT_803e8d5c - *(float *)(*(int *)(param_1 + 0xb8) + 2000);
  if (FLOAT_803e8d70 <= FLOAT_803df0f8) {
    if (FLOAT_803e8b3c < local_48) {
      FLOAT_803df0f8 = FLOAT_803e8d5c;
      local_48 = local_48 + *(float *)(param_1 + 0x10);
      iVar2 = 0;
      dVar4 = (double)FLOAT_803e8b70;
      dVar3 = DOUBLE_803e8b58;
      do {
        uStack_3c = FUN_80022264(0xffffff9c,100);
        uStack_3c = uStack_3c ^ 0x80000000;
        local_40 = 0x43300000;
        local_4c = *(float *)(param_1 + 0xc) +
                   (float)((double)(float)((double)CONCAT44(0x43300000,uStack_3c) - dVar3) / dVar4);
        uStack_34 = FUN_80022264(0xffffff9c,100);
        uStack_34 = uStack_34 ^ 0x80000000;
        local_38 = 0x43300000;
        local_44 = *(float *)(param_1 + 0x14) +
                   (float)((double)(float)((double)CONCAT44(0x43300000,uStack_34) - dVar3) / dVar4);
        uVar1 = FUN_80022264(0,2);
        (**(code **)(*DAT_803dd708 + 8))(param_1,uVar1 + 0x3f4,auStack_58,1,0xffffffff,0);
        uVar1 = FUN_80022264(0,2);
        (**(code **)(*DAT_803dd708 + 8))(param_1,uVar1 + 0x3f7,auStack_58,1,0xffffffff,0);
        iVar2 = iVar2 + 1;
      } while (iVar2 < 10);
    }
    else {
      FLOAT_803df0f8 = -(FLOAT_803e8bac * FLOAT_803dc074 - FLOAT_803df0f8);
    }
  }
  else {
    *(undefined *)(*(int *)(param_1 + 0xb8) + 0x8ca) = 0;
  }
  return;
}

