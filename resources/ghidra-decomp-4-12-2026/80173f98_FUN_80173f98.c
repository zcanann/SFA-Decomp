// Function: FUN_80173f98
// Entry: 80173f98
// Size: 1172 bytes

/* WARNING: Removing unreachable block (ram,0x80174404) */
/* WARNING: Removing unreachable block (ram,0x801743fc) */
/* WARNING: Removing unreachable block (ram,0x80173fb0) */
/* WARNING: Removing unreachable block (ram,0x80173fa8) */

void FUN_80173f98(int param_1,int param_2)

{
  short sVar1;
  float fVar2;
  uint uVar3;
  int iVar4;
  int iVar5;
  double dVar6;
  double dVar7;
  undefined local_58 [4];
  undefined2 local_54 [2];
  undefined2 local_50 [4];
  undefined4 local_48;
  uint uStack_44;
  undefined4 local_40;
  uint uStack_3c;
  undefined4 local_38;
  uint uStack_34;
  
  iVar5 = *(int *)(param_1 + 0xb8);
  local_58[0] = 3;
  local_50[0] = DAT_803e4140;
  local_54[0] = DAT_803e4144;
  uVar3 = FUN_80022264(0,0xffff);
  uStack_44 = FUN_80022264(0x27,0x2c);
  uStack_44 = uStack_44 ^ 0x80000000;
  local_48 = 0x43300000;
  dVar7 = (double)((float)((double)CONCAT44(0x43300000,uStack_44) - DOUBLE_803e4198) /
                  FLOAT_803e417c);
  uStack_3c = uVar3 ^ 0x80000000;
  local_40 = 0x43300000;
  dVar6 = (double)FUN_802945e0();
  *(float *)(param_1 + 0x24) = (float)(dVar7 * dVar6);
  dVar6 = (double)FUN_80294964();
  *(float *)(param_1 + 0x2c) = (float)(dVar7 * dVar6);
  uStack_34 = FUN_80022264(0x28,0x32);
  uStack_34 = uStack_34 ^ 0x80000000;
  local_38 = 0x43300000;
  *(float *)(param_1 + 0x28) =
       (float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e4198) / FLOAT_803e4188;
  sVar1 = *(short *)(param_2 + 0x2e);
  if (sVar1 == 1) {
    *(byte *)(iVar5 + 0x27a) = *(byte *)(iVar5 + 0x27a) | 1;
    *(undefined *)(param_1 + 0x36) = 1;
  }
  else if (sVar1 == 2) {
    *(byte *)(iVar5 + 0x27a) = *(byte *)(iVar5 + 0x27a) | 1;
    *(undefined *)(param_1 + 0x36) = 1;
    if (*(int *)(param_1 + 0x54) != 0) {
      FUN_80035ff8(param_1);
    }
    iVar4 = FUN_8002bac4();
    fVar2 = FLOAT_803e418c;
    *(float *)(param_1 + 0x24) =
         (*(float *)(iVar4 + 0xc) - *(float *)(param_1 + 0xc)) / FLOAT_803e418c;
    *(float *)(param_1 + 0x28) = (*(float *)(iVar4 + 0x10) - *(float *)(param_1 + 0x10)) / fVar2;
    *(float *)(param_1 + 0x2c) = (*(float *)(iVar4 + 0x14) - *(float *)(param_1 + 0x14)) / fVar2;
  }
  else if (sVar1 == 3) {
    *(byte *)(iVar5 + 0x27a) = *(byte *)(iVar5 + 0x27a) | 1;
    *(undefined *)(param_1 + 0x36) = 1;
    uStack_34 = FUN_80022264(0x8c,0x96);
    uStack_34 = uStack_34 ^ 0x80000000;
    local_38 = 0x43300000;
    *(float *)(param_1 + 0x28) =
         -((float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e4198) / FLOAT_803e4188);
  }
  *(undefined *)(param_1 + 0xad) = *(undefined *)(param_2 + 0x26);
  if (*(char *)(*(int *)(param_1 + 0x50) + 0x55) <= *(char *)(param_1 + 0xad)) {
    *(undefined *)(param_1 + 0xad) = 0;
  }
  if (*(int *)(param_1 + 100) != 0) {
    *(undefined *)(*(int *)(param_1 + 100) + 0x3a) = 100;
    *(undefined *)(*(int *)(param_1 + 100) + 0x3b) = 0x96;
  }
  iVar4 = FUN_8002b660(param_1);
  sVar1 = *(short *)(param_1 + 0x46);
  if (sVar1 == 0x2cd) {
    uVar3 = FUN_80022264(0,1);
    *(undefined *)(*(int *)(iVar4 + 0x34) + 8) = *(undefined *)((int)local_54 + uVar3);
    *(undefined2 *)(iVar5 + 0x272) = 0x54e;
    *(undefined2 *)(iVar5 + 0x270) = 0x54a;
    *(undefined2 *)(iVar5 + 0x274) = 0x59;
    *(undefined2 *)(iVar5 + 0x276) = 0x5b1;
    *(undefined *)(iVar5 + 0x27c) = 1;
  }
  else {
    if (sVar1 < 0x2cd) {
      if (sVar1 == 0x2c4) {
        uVar3 = FUN_80022264(0,1);
        *(undefined *)(*(int *)(iVar4 + 0x34) + 8) = *(undefined *)((int)local_50 + uVar3);
        *(undefined2 *)(iVar5 + 0x272) = 0x54f;
        *(undefined2 *)(iVar5 + 0x270) = 0x54b;
        *(undefined2 *)(iVar5 + 0x274) = 0x58;
        *(undefined2 *)(iVar5 + 0x276) = 0x5b0;
        *(undefined *)(iVar5 + 0x27c) = 4;
        goto LAB_80174324;
      }
    }
    else if ((sVar1 != 0x2cf) && (sVar1 < 0x2cf)) {
      *(undefined *)(*(int *)(iVar4 + 0x34) + 8) = 3;
      *(undefined2 *)(iVar5 + 0x272) = 0x54d;
      *(undefined2 *)(iVar5 + 0x270) = 0x549;
      *(undefined2 *)(iVar5 + 0x274) = 0x5a;
      *(undefined2 *)(iVar5 + 0x276) = 0x5b2;
      *(undefined *)(iVar5 + 0x27c) = 2;
      goto LAB_80174324;
    }
    *(undefined *)(*(int *)(iVar4 + 0x34) + 8) = 2;
    *(undefined2 *)(iVar5 + 0x272) = 0x550;
    *(undefined2 *)(iVar5 + 0x270) = 0x54c;
    *(undefined2 *)(iVar5 + 0x274) = 0x5b;
    *(undefined2 *)(iVar5 + 0x276) = 0x5b3;
    *(undefined *)(iVar5 + 0x27c) = 6;
  }
LAB_80174324:
  *(float *)(iVar5 + 0x268) = FLOAT_803e4190;
  if ((*(ushort *)(param_1 + 6) & 0x2000) != 0) {
    (**(code **)(*DAT_803dd728 + 4))(iVar5,0,0x40007,0);
    (**(code **)(*DAT_803dd728 + 0xc))(iVar5,1,&DAT_80321908,iVar5 + 0x268,local_58);
    (**(code **)(*DAT_803dd728 + 0x20))(param_1,iVar5);
  }
  *(ushort *)(param_1 + 0xb0) = *(ushort *)(param_1 + 0xb0) | 0x2000;
  if ((*(byte *)(iVar5 + 0x27a) & 1) == 0) {
    *(float *)(iVar5 + 0x26c) = FLOAT_803e4160;
    *(byte *)(iVar5 + 0x27a) = *(byte *)(iVar5 + 0x27a) | 4;
  }
  else {
    *(float *)(iVar5 + 0x26c) = FLOAT_803e4194;
  }
  FUN_80037a5c(param_1,1);
  return;
}

