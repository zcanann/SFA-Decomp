// Function: FUN_80173aec
// Entry: 80173aec
// Size: 1172 bytes

/* WARNING: Removing unreachable block (ram,0x80173f50) */
/* WARNING: Removing unreachable block (ram,0x80173f58) */

void FUN_80173aec(int param_1,int param_2)

{
  short sVar1;
  float fVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  undefined4 uVar6;
  double dVar7;
  undefined8 in_f30;
  double dVar8;
  undefined8 in_f31;
  double dVar9;
  undefined local_58 [4];
  undefined2 local_54;
  undefined2 local_50;
  undefined4 local_48;
  uint uStack68;
  undefined4 local_40;
  uint uStack60;
  undefined4 local_38;
  uint uStack52;
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar6 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  __psq_st0(auStack24,(int)((ulonglong)in_f30 >> 0x20),0);
  __psq_st1(auStack24,(int)in_f30,0);
  iVar5 = *(int *)(param_1 + 0xb8);
  local_58[0] = 3;
  local_50 = DAT_803e34a8;
  local_54 = DAT_803e34ac;
  uStack60 = FUN_800221a0(0,0xffff);
  uStack68 = FUN_800221a0(0x27,0x2c);
  uStack68 = uStack68 ^ 0x80000000;
  local_48 = 0x43300000;
  dVar8 = (double)((float)((double)CONCAT44(0x43300000,uStack68) - DOUBLE_803e3500) / FLOAT_803e34e4
                  );
  uStack60 = uStack60 ^ 0x80000000;
  local_40 = 0x43300000;
  dVar9 = (double)((FLOAT_803e34e8 *
                   (float)((double)CONCAT44(0x43300000,uStack60) - DOUBLE_803e3500)) /
                  FLOAT_803e34ec);
  dVar7 = (double)FUN_80293e80(dVar9);
  *(float *)(param_1 + 0x24) = (float)(dVar8 * dVar7);
  dVar7 = (double)FUN_80294204(dVar9);
  *(float *)(param_1 + 0x2c) = (float)(dVar8 * dVar7);
  uStack52 = FUN_800221a0(0x28,0x32);
  uStack52 = uStack52 ^ 0x80000000;
  local_38 = 0x43300000;
  *(float *)(param_1 + 0x28) =
       (float)((double)CONCAT44(0x43300000,uStack52) - DOUBLE_803e3500) / FLOAT_803e34f0;
  sVar1 = *(short *)(param_2 + 0x2e);
  if (sVar1 == 1) {
    *(byte *)(iVar5 + 0x27a) = *(byte *)(iVar5 + 0x27a) | 1;
    *(undefined *)(param_1 + 0x36) = 1;
  }
  else if (sVar1 == 2) {
    *(byte *)(iVar5 + 0x27a) = *(byte *)(iVar5 + 0x27a) | 1;
    *(undefined *)(param_1 + 0x36) = 1;
    if (*(int *)(param_1 + 0x54) != 0) {
      FUN_80035f00(param_1);
    }
    iVar3 = FUN_8002b9ec();
    fVar2 = FLOAT_803e34f4;
    *(float *)(param_1 + 0x24) =
         (*(float *)(iVar3 + 0xc) - *(float *)(param_1 + 0xc)) / FLOAT_803e34f4;
    *(float *)(param_1 + 0x28) = (*(float *)(iVar3 + 0x10) - *(float *)(param_1 + 0x10)) / fVar2;
    *(float *)(param_1 + 0x2c) = (*(float *)(iVar3 + 0x14) - *(float *)(param_1 + 0x14)) / fVar2;
  }
  else if (sVar1 == 3) {
    *(byte *)(iVar5 + 0x27a) = *(byte *)(iVar5 + 0x27a) | 1;
    *(undefined *)(param_1 + 0x36) = 1;
    uStack52 = FUN_800221a0(0x8c,0x96);
    uStack52 = uStack52 ^ 0x80000000;
    local_38 = 0x43300000;
    *(float *)(param_1 + 0x28) =
         -((float)((double)CONCAT44(0x43300000,uStack52) - DOUBLE_803e3500) / FLOAT_803e34f0);
  }
  *(undefined *)(param_1 + 0xad) = *(undefined *)(param_2 + 0x26);
  if (*(char *)(*(int *)(param_1 + 0x50) + 0x55) <= *(char *)(param_1 + 0xad)) {
    *(undefined *)(param_1 + 0xad) = 0;
  }
  if (*(int *)(param_1 + 100) != 0) {
    *(undefined *)(*(int *)(param_1 + 100) + 0x3a) = 100;
    *(undefined *)(*(int *)(param_1 + 100) + 0x3b) = 0x96;
  }
  iVar3 = FUN_8002b588(param_1);
  sVar1 = *(short *)(param_1 + 0x46);
  if (sVar1 == 0x2cd) {
    iVar4 = FUN_800221a0(0,1);
    *(undefined *)(*(int *)(iVar3 + 0x34) + 8) = *(undefined *)((int)&local_54 + iVar4);
    *(undefined2 *)(iVar5 + 0x272) = 0x54e;
    *(undefined2 *)(iVar5 + 0x270) = 0x54a;
    *(undefined2 *)(iVar5 + 0x274) = 0x59;
    *(undefined2 *)(iVar5 + 0x276) = 0x5b1;
    *(undefined *)(iVar5 + 0x27c) = 1;
  }
  else {
    if (sVar1 < 0x2cd) {
      if (sVar1 == 0x2c4) {
        iVar4 = FUN_800221a0(0,1);
        *(undefined *)(*(int *)(iVar3 + 0x34) + 8) = *(undefined *)((int)&local_50 + iVar4);
        *(undefined2 *)(iVar5 + 0x272) = 0x54f;
        *(undefined2 *)(iVar5 + 0x270) = 0x54b;
        *(undefined2 *)(iVar5 + 0x274) = 0x58;
        *(undefined2 *)(iVar5 + 0x276) = 0x5b0;
        *(undefined *)(iVar5 + 0x27c) = 4;
        goto LAB_80173e78;
      }
    }
    else if ((sVar1 != 0x2cf) && (sVar1 < 0x2cf)) {
      *(undefined *)(*(int *)(iVar3 + 0x34) + 8) = 3;
      *(undefined2 *)(iVar5 + 0x272) = 0x54d;
      *(undefined2 *)(iVar5 + 0x270) = 0x549;
      *(undefined2 *)(iVar5 + 0x274) = 0x5a;
      *(undefined2 *)(iVar5 + 0x276) = 0x5b2;
      *(undefined *)(iVar5 + 0x27c) = 2;
      goto LAB_80173e78;
    }
    *(undefined *)(*(int *)(iVar3 + 0x34) + 8) = 2;
    *(undefined2 *)(iVar5 + 0x272) = 0x550;
    *(undefined2 *)(iVar5 + 0x270) = 0x54c;
    *(undefined2 *)(iVar5 + 0x274) = 0x5b;
    *(undefined2 *)(iVar5 + 0x276) = 0x5b3;
    *(undefined *)(iVar5 + 0x27c) = 6;
  }
LAB_80173e78:
  *(float *)(iVar5 + 0x268) = FLOAT_803e34f8;
  if ((*(ushort *)(param_1 + 6) & 0x2000) != 0) {
    (**(code **)(*DAT_803dcaa8 + 4))(iVar5,0,0x40007,0);
    (**(code **)(*DAT_803dcaa8 + 0xc))(iVar5,1,&DAT_80320cb8,iVar5 + 0x268,local_58);
    (**(code **)(*DAT_803dcaa8 + 0x20))(param_1,iVar5);
  }
  *(ushort *)(param_1 + 0xb0) = *(ushort *)(param_1 + 0xb0) | 0x2000;
  if ((*(byte *)(iVar5 + 0x27a) & 1) == 0) {
    *(float *)(iVar5 + 0x26c) = FLOAT_803e34c8;
    *(byte *)(iVar5 + 0x27a) = *(byte *)(iVar5 + 0x27a) | 4;
  }
  else {
    *(float *)(iVar5 + 0x26c) = FLOAT_803e34fc;
  }
  FUN_80037964(param_1,1);
  __psq_l0(auStack8,uVar6);
  __psq_l1(auStack8,uVar6);
  __psq_l0(auStack24,uVar6);
  __psq_l1(auStack24,uVar6);
  return;
}

