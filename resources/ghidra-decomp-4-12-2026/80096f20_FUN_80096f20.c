// Function: FUN_80096f20
// Entry: 80096f20
// Size: 776 bytes

/* WARNING: Removing unreachable block (ram,0x80097208) */
/* WARNING: Removing unreachable block (ram,0x80097200) */
/* WARNING: Removing unreachable block (ram,0x800971f8) */
/* WARNING: Removing unreachable block (ram,0x800971f0) */
/* WARNING: Removing unreachable block (ram,0x800971e8) */
/* WARNING: Removing unreachable block (ram,0x800971e0) */
/* WARNING: Removing unreachable block (ram,0x80096f58) */
/* WARNING: Removing unreachable block (ram,0x80096f50) */
/* WARNING: Removing unreachable block (ram,0x80096f48) */
/* WARNING: Removing unreachable block (ram,0x80096f40) */
/* WARNING: Removing unreachable block (ram,0x80096f38) */
/* WARNING: Removing unreachable block (ram,0x80096f30) */

void FUN_80096f20(undefined4 param_1,undefined4 param_2,uint param_3,int param_4,ushort param_5)

{
  uint uVar1;
  ushort uVar2;
  uint uVar3;
  undefined4 uVar4;
  uint uVar5;
  int iVar6;
  double extraout_f1;
  double in_f26;
  double dVar7;
  double in_f27;
  double dVar8;
  double in_f28;
  double dVar9;
  double in_f29;
  double dVar10;
  double in_f30;
  double dVar11;
  double in_f31;
  double dVar12;
  double in_ps26_1;
  double in_ps27_1;
  double in_ps28_1;
  double in_ps29_1;
  double in_ps30_1;
  double in_ps31_1;
  undefined8 uVar13;
  ushort local_f8;
  undefined2 local_f6;
  undefined2 local_f4;
  undefined auStack_f0 [2];
  undefined2 local_ee;
  ushort local_ec;
  undefined2 local_ea;
  float local_e8;
  float local_e4;
  float local_e0;
  float local_dc;
  undefined4 local_d8;
  undefined4 local_d4;
  undefined4 local_d0;
  undefined4 local_cc;
  undefined4 local_c8;
  undefined4 local_c4;
  undefined4 local_c0;
  undefined4 local_bc;
  undefined4 local_b8;
  undefined4 local_b4;
  undefined4 local_b0;
  undefined4 local_ac;
  undefined4 local_a8;
  undefined4 local_a0;
  uint uStack_9c;
  float local_58;
  float fStack_54;
  float local_48;
  float fStack_44;
  float local_38;
  float fStack_34;
  float local_28;
  float fStack_24;
  float local_18;
  float fStack_14;
  float local_8;
  float fStack_4;
  
  local_8 = (float)in_f31;
  fStack_4 = (float)in_ps31_1;
  local_18 = (float)in_f30;
  fStack_14 = (float)in_ps30_1;
  local_28 = (float)in_f29;
  fStack_24 = (float)in_ps29_1;
  local_38 = (float)in_f28;
  fStack_34 = (float)in_ps28_1;
  local_48 = (float)in_f27;
  fStack_44 = (float)in_ps27_1;
  local_58 = (float)in_f26;
  fStack_54 = (float)in_ps26_1;
  uVar13 = FUN_80286828();
  uVar4 = (undefined4)((ulonglong)uVar13 >> 0x20);
  local_d8 = DAT_802c28ac;
  local_d4 = DAT_802c28b0;
  local_d0 = DAT_802c28b4;
  local_cc = DAT_802c28b8;
  local_c8 = DAT_802c28bc;
  local_c4 = DAT_802c28c0;
  local_c0 = DAT_802c28c4;
  local_bc = DAT_802c28c8;
  local_b8 = DAT_802c28cc;
  local_b4 = DAT_802c28d0;
  local_b0 = DAT_802c28d4;
  local_ac = DAT_802c28d8;
  local_a8 = DAT_802c28dc;
  uVar3 = (uint)DAT_803dc070;
  if (3 < uVar3) {
    uVar3 = 3;
  }
  uVar1 = (uint)uVar13 & 0xff;
  uVar2 = param_5 & 0xff;
  dVar8 = (double)FLOAT_803dffe8;
  dVar9 = (double)FLOAT_803dffd4;
  dVar10 = (double)FLOAT_803dffdc;
  dVar11 = extraout_f1;
  dVar12 = DOUBLE_803dffe0;
  for (iVar6 = 0; iVar6 < (int)(uVar3 * (param_3 & 0xff)); iVar6 = iVar6 + 1) {
    uStack_9c = FUN_80022264(0,1000);
    uStack_9c = uStack_9c ^ 0x80000000;
    local_a0 = 0x43300000;
    dVar7 = (double)(float)((double)(float)((double)CONCAT44(0x43300000,uStack_9c) - dVar12) / dVar8
                           );
    uVar5 = FUN_80022264(0,0xffff);
    local_f8 = (ushort)uVar5;
    uVar5 = FUN_80022264(0,0xffff);
    local_f6 = (undefined2)uVar5;
    uVar5 = FUN_80022264(0,0xffff);
    local_f4 = (undefined2)uVar5;
    local_e4 = (float)(dVar11 * -(double)(float)(dVar7 * (double)(float)(dVar7 * dVar7) - dVar9));
    local_e0 = (float)dVar10;
    local_dc = (float)dVar10;
    FUN_80021b8c(&local_f8,&local_e4);
    if (param_4 != 0) {
      local_e4 = local_e4 + *(float *)(param_4 + 0xc);
      local_e0 = local_e0 + *(float *)(param_4 + 0x10);
      local_dc = local_dc + *(float *)(param_4 + 0x14);
    }
    local_ea = *(undefined2 *)(&local_d8 + uVar1);
    local_ee = *(undefined2 *)((int)&local_d8 + uVar1 * 4 + 2);
    local_e8 = (float)dVar9;
    local_ec = uVar2;
    if ((uVar1 < 9) || (0xb < uVar1)) {
      (**(code **)(*DAT_803dd708 + 8))(uVar4,0x7e2,auStack_f0,2,0xffffffff,0);
    }
    else {
      if ((uVar1 == 0xb) || (uVar1 == 10)) {
        (**(code **)(*DAT_803dd708 + 8))(uVar4,0x7e3,auStack_f0,2,0xffffffff,0);
      }
      uVar5 = (uint)uVar13 & 0xff;
      if ((uVar5 == 0xb) || (uVar5 == 9)) {
        (**(code **)(*DAT_803dd708 + 8))(uVar4,0x7e4,auStack_f0,2,0xffffffff,0);
      }
    }
  }
  FUN_80286874();
  return;
}

