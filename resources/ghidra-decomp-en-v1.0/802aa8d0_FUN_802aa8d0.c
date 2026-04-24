// Function: FUN_802aa8d0
// Entry: 802aa8d0
// Size: 432 bytes

/* WARNING: Removing unreachable block (ram,0x802aaa54) */
/* WARNING: Removing unreachable block (ram,0x802aaa5c) */

void FUN_802aa8d0(int param_1)

{
  int iVar1;
  int iVar2;
  undefined4 uVar3;
  undefined8 in_f30;
  double dVar4;
  undefined8 in_f31;
  double dVar5;
  undefined auStack88 [12];
  float local_4c;
  float local_48;
  float local_44;
  undefined4 local_40;
  uint uStack60;
  undefined4 local_38;
  uint uStack52;
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar3 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  __psq_st0(auStack24,(int)((ulonglong)in_f30 >> 0x20),0);
  __psq_st1(auStack24,(int)in_f30,0);
  local_48 = FLOAT_803e80c4 - *(float *)(*(int *)(param_1 + 0xb8) + 2000);
  if (FLOAT_803e80d8 <= FLOAT_803de478) {
    if (FLOAT_803e7ea4 < local_48) {
      FLOAT_803de478 = FLOAT_803e80c4;
      local_48 = local_48 + *(float *)(param_1 + 0x10);
      iVar2 = 0;
      dVar5 = (double)FLOAT_803e7ed8;
      dVar4 = DOUBLE_803e7ec0;
      do {
        uStack60 = FUN_800221a0(0xffffff9c,100);
        uStack60 = uStack60 ^ 0x80000000;
        local_40 = 0x43300000;
        local_4c = *(float *)(param_1 + 0xc) +
                   (float)((double)(float)((double)CONCAT44(0x43300000,uStack60) - dVar4) / dVar5);
        uStack52 = FUN_800221a0(0xffffff9c,100);
        uStack52 = uStack52 ^ 0x80000000;
        local_38 = 0x43300000;
        local_44 = *(float *)(param_1 + 0x14) +
                   (float)((double)(float)((double)CONCAT44(0x43300000,uStack52) - dVar4) / dVar5);
        iVar1 = FUN_800221a0(0,2);
        (**(code **)(*DAT_803dca88 + 8))(param_1,iVar1 + 0x3f4,auStack88,1,0xffffffff,0);
        iVar1 = FUN_800221a0(0,2);
        (**(code **)(*DAT_803dca88 + 8))(param_1,iVar1 + 0x3f7,auStack88,1,0xffffffff,0);
        iVar2 = iVar2 + 1;
      } while (iVar2 < 10);
    }
    else {
      FLOAT_803de478 = -(FLOAT_803e7f14 * FLOAT_803db414 - FLOAT_803de478);
    }
  }
  else {
    *(undefined *)(*(int *)(param_1 + 0xb8) + 0x8ca) = 0;
  }
  __psq_l0(auStack8,uVar3);
  __psq_l1(auStack8,uVar3);
  __psq_l0(auStack24,uVar3);
  __psq_l1(auStack24,uVar3);
  return;
}

