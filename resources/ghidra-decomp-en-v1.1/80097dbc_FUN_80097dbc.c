// Function: FUN_80097dbc
// Entry: 80097dbc
// Size: 1140 bytes

/* WARNING: Removing unreachable block (ram,0x80098210) */
/* WARNING: Removing unreachable block (ram,0x80098208) */
/* WARNING: Removing unreachable block (ram,0x80098200) */
/* WARNING: Removing unreachable block (ram,0x80097ddc) */
/* WARNING: Removing unreachable block (ram,0x80097dd4) */
/* WARNING: Removing unreachable block (ram,0x80097dcc) */

void FUN_80097dbc(undefined8 param_1,double param_2,double param_3,double param_4,undefined4 param_5
                 ,undefined4 param_6,uint param_7,uint param_8,uint param_9,int param_10,
                 uint param_11)

{
  int iVar1;
  uint uVar2;
  int iVar3;
  double dVar4;
  double dVar5;
  double dVar6;
  double extraout_f1;
  double in_f29;
  double in_f30;
  double in_f31;
  double in_ps29_1;
  double in_ps30_1;
  double in_ps31_1;
  undefined8 uVar7;
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
  undefined4 local_a4;
  undefined4 local_a0;
  undefined4 local_9c;
  undefined2 local_98;
  undefined2 local_94;
  undefined2 local_92;
  undefined2 local_90;
  undefined2 local_8e;
  float local_8c;
  float local_88;
  float local_84;
  float local_80;
  undefined4 local_78;
  uint uStack_74;
  undefined4 local_70;
  uint uStack_6c;
  undefined8 local_68;
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
  uVar7 = FUN_8028682c();
  local_a8 = DAT_802c27a0;
  local_a4 = DAT_802c27a4;
  local_a0 = DAT_802c27a8;
  local_9c = DAT_802c27ac;
  local_98 = DAT_802c27b0;
  local_b8 = DAT_802c27b4;
  local_b4 = DAT_802c27b8;
  local_b0 = DAT_802c27bc;
  local_ac = DAT_802c27c0;
  local_c8 = DAT_802c27c4;
  local_c4 = DAT_802c27c8;
  local_c0 = DAT_802c27cc;
  local_bc = DAT_802c27d0;
  local_d8 = DAT_802c27d4;
  local_d4 = DAT_802c27d8;
  local_d0 = DAT_802c27dc;
  local_cc = DAT_802c27e0;
  local_8c = (float)extraout_f1;
  local_8e = *(undefined2 *)((int)&local_a8 + (param_7 & 0xff) * 2);
  local_92 = 0x3c;
  iVar3 = 0;
  iVar1 = ((uint)uVar7 & 0xff) * 2;
  do {
    uVar2 = FUN_80022264(0,99);
    if ((int)uVar2 < (int)(param_9 & 0xff)) {
      uStack_74 = FUN_80022264(0,1000);
      uStack_74 = uStack_74 ^ 0x80000000;
      local_78 = 0x43300000;
      local_88 = (float)((double)CONCAT44(0x43300000,uStack_74) - DOUBLE_803dffe0) / FLOAT_803dffe8;
      uStack_6c = FUN_80022264(0,1000);
      uStack_6c = uStack_6c ^ 0x80000000;
      local_70 = 0x43300000;
      local_84 = (float)((double)CONCAT44(0x43300000,uStack_6c) - DOUBLE_803dffe0) / FLOAT_803dffe8;
      uVar2 = FUN_80022264(0,1000);
      local_68 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_80 = (float)(local_68 - DOUBLE_803dffe0) / FLOAT_803dffe8;
      switch(param_8 & 0xff) {
      case 1:
        local_88 = local_88 - FLOAT_803dffd8;
        local_84 = local_84 - FLOAT_803dffd8;
        local_80 = local_80 - FLOAT_803dffd8;
        break;
      case 2:
        local_88 = local_88 - FLOAT_803dffd8;
        local_84 = local_84 * local_84 * local_84 - FLOAT_803dffd8;
        local_80 = local_80 - FLOAT_803dffd8;
        break;
      case 3:
        local_88 = local_88 - FLOAT_803dffd8;
        local_84 = (FLOAT_803dffd4 - local_84 * local_84 * local_84) - FLOAT_803dffd8;
        local_80 = local_80 - FLOAT_803dffd8;
        break;
      case 4:
        local_88 = local_88 - FLOAT_803dffd8;
        local_68 = (double)(longlong)(int)(FLOAT_803dffd0 * local_84);
        uStack_6c = (int)(FLOAT_803dffd0 * local_84) & 0xffff;
        local_70 = 0x43300000;
        dVar4 = (double)FUN_80294964();
        local_84 = (float)((double)FLOAT_803dffd8 * dVar4);
        local_80 = (float)((double)local_80 - (double)FLOAT_803dffd8);
        break;
      case 5:
        local_88 = local_88 - FLOAT_803dffd8;
        local_68 = (double)(longlong)(int)(FLOAT_803dffd0 * local_84);
        uStack_6c = (int)(FLOAT_803dffd0 * local_84) & 0xffff;
        local_70 = 0x43300000;
        dVar4 = (double)FUN_802945e0();
        local_84 = (float)((double)FLOAT_803dffd8 * dVar4);
        local_80 = (float)((double)local_80 - (double)FLOAT_803dffd8);
        break;
      case 6:
        local_88 = local_88 - FLOAT_803dffd8;
        local_84 = local_84 - FLOAT_803dffd8;
        local_80 = local_80 - FLOAT_803dffd8;
        break;
      case 7:
        local_88 = local_88 - FLOAT_803dffd8;
        local_84 = local_84 - FLOAT_803dffd8;
        local_80 = local_80 - FLOAT_803dffd8;
      }
      dVar4 = (double)local_88;
      local_88 = (float)(dVar4 * param_2);
      dVar5 = (double)local_84;
      local_84 = (float)(dVar5 * param_3);
      dVar6 = (double)local_80;
      local_80 = (float)(dVar6 * param_4);
      if (param_10 != 0) {
        local_88 = (float)(dVar4 * param_2) + *(float *)(param_10 + 0xc);
        local_84 = (float)(dVar5 * param_3) + *(float *)(param_10 + 0x10);
        local_80 = (float)(dVar6 * param_4) + *(float *)(param_10 + 0x14);
      }
      local_90 = *(undefined2 *)((int)&local_c8 + iVar1);
      local_94 = *(undefined2 *)((int)&local_d8 + iVar1);
      (**(code **)(*DAT_803dd708 + 8))
                ((int)((ulonglong)uVar7 >> 0x20),*(undefined2 *)((int)&local_b8 + iVar1),&local_94,
                 param_11 | 2,0xffffffff,0);
    }
    iVar3 = iVar3 + 1;
  } while (iVar3 < 4);
  FUN_80286878();
  return;
}

