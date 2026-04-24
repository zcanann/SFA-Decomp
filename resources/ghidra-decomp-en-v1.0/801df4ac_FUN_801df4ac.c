// Function: FUN_801df4ac
// Entry: 801df4ac
// Size: 928 bytes

/* WARNING: Removing unreachable block (ram,0x801df81c) */
/* WARNING: Removing unreachable block (ram,0x801df824) */

undefined4 FUN_801df4ac(undefined4 param_1,undefined4 param_2,int param_3)

{
  byte bVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  undefined4 uVar6;
  undefined8 in_f30;
  double dVar7;
  undefined8 in_f31;
  double dVar8;
  int local_58;
  undefined auStack84 [4];
  int local_50;
  undefined auStack76 [4];
  undefined2 local_48;
  undefined2 local_46;
  undefined2 local_44;
  float local_40;
  float local_3c;
  float local_38;
  float local_34;
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar6 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  __psq_st0(auStack24,(int)((ulonglong)in_f30 >> 0x20),0);
  __psq_st1(auStack24,(int)in_f30,0);
  iVar5 = 0;
  dVar7 = (double)FLOAT_803e56b0;
  dVar8 = (double)FLOAT_803e56b4;
  for (iVar4 = 0; iVar4 < (int)(uint)*(byte *)(param_3 + 0x8b); iVar4 = iVar4 + 1) {
    local_3c = (float)dVar7;
    local_38 = (float)dVar7;
    local_34 = (float)dVar7;
    local_40 = (float)dVar8;
    local_46 = 0;
    local_48 = 0;
    local_44 = 0;
    bVar1 = *(byte *)(param_3 + iVar4 + 0x81);
    if (bVar1 == 4) {
      local_44 = 2;
      (**(code **)(*DAT_803dca88 + 8))(param_1,0x85,&local_48,1,0xffffffff,0);
    }
    else if (bVar1 < 4) {
      if (bVar1 == 2) {
        local_44 = 0;
        (**(code **)(*DAT_803dca88 + 8))(param_1,0x85,&local_48,1,0xffffffff,0);
      }
      else if (bVar1 < 2) {
        if (bVar1 != 0) {
          FUN_800200e8(0x75,1);
        }
      }
      else {
        local_44 = 1;
        (**(code **)(*DAT_803dca88 + 8))(param_1,0x85,&local_48,1,0xffffffff,0);
      }
    }
    else if (bVar1 == 6) {
      local_44 = 4;
      (**(code **)(*DAT_803dca88 + 8))(param_1,0x85,&local_48,1,0xffffffff,0);
    }
    else if (bVar1 < 6) {
      local_44 = 3;
      (**(code **)(*DAT_803dca88 + 8))(param_1,0x85,&local_48,1,0xffffffff,0);
    }
  }
  while (iVar4 = FUN_800374ec(param_1,&local_50,auStack76,auStack84), iVar4 != 0) {
    if ((*(byte *)(param_3 + 0x90) & 0x80) == 0) {
      if (local_50 == 0xf000c) {
        iVar2 = FUN_80036f50(3,&local_58);
        for (iVar4 = 0; iVar4 < local_58; iVar4 = iVar4 + 1) {
          iVar3 = *(int *)(iVar2 + iVar4 * 4);
          if (*(short *)(iVar3 + 0x46) == 0xf7) {
            iVar4 = local_58;
            iVar5 = iVar3;
          }
        }
        if (iVar5 != 0) {
          FUN_800378c4(iVar5,0x130002,param_1,0);
        }
      }
      else if (local_50 < 0xf000c) {
        if (0xf000a < local_50) {
          iVar2 = FUN_80036f50(3,&local_58);
          for (iVar4 = 0; iVar4 < local_58; iVar4 = iVar4 + 1) {
            iVar3 = *(int *)(iVar2 + iVar4 * 4);
            if (*(short *)(iVar3 + 0x46) == 0xf7) {
              iVar4 = local_58;
              iVar5 = iVar3;
            }
          }
          if (iVar5 != 0) {
            FUN_800378c4(iVar5,0x130001,param_1,0);
          }
        }
      }
      else if (local_50 < 0xf000e) {
        iVar2 = FUN_80036f50(3,&local_58);
        for (iVar4 = 0; iVar4 < local_58; iVar4 = iVar4 + 1) {
          iVar3 = *(int *)(iVar2 + iVar4 * 4);
          if (*(short *)(iVar3 + 0x46) == 0xf7) {
            iVar4 = local_58;
            iVar5 = iVar3;
          }
        }
        if (iVar5 != 0) {
          FUN_800378c4(iVar5,0x130003,param_1,0);
        }
      }
    }
  }
  *(undefined *)(param_3 + 0x56) = 0;
  __psq_l0(auStack8,uVar6);
  __psq_l1(auStack8,uVar6);
  __psq_l0(auStack24,uVar6);
  __psq_l1(auStack24,uVar6);
  return 0;
}

