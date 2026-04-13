// Function: FUN_800979c0
// Entry: 800979c0
// Size: 1020 bytes

/* WARNING: Removing unreachable block (ram,0x80097d9c) */
/* WARNING: Removing unreachable block (ram,0x80097d94) */
/* WARNING: Removing unreachable block (ram,0x80097d8c) */
/* WARNING: Removing unreachable block (ram,0x80097d84) */
/* WARNING: Removing unreachable block (ram,0x80097d7c) */
/* WARNING: Removing unreachable block (ram,0x800979f0) */
/* WARNING: Removing unreachable block (ram,0x800979e8) */
/* WARNING: Removing unreachable block (ram,0x800979e0) */
/* WARNING: Removing unreachable block (ram,0x800979d8) */
/* WARNING: Removing unreachable block (ram,0x800979d0) */

void FUN_800979c0(undefined8 param_1,double param_2,double param_3,double param_4,undefined4 param_5
                 ,undefined4 param_6,uint param_7,uint param_8,uint param_9,int param_10,
                 uint param_11)

{
  int iVar1;
  uint uVar2;
  int iVar3;
  double extraout_f1;
  double in_f27;
  double in_f28;
  double in_f29;
  double dVar4;
  double in_f30;
  double dVar5;
  double in_f31;
  double dVar6;
  double in_ps27_1;
  double in_ps28_1;
  double in_ps29_1;
  double in_ps30_1;
  double in_ps31_1;
  undefined8 uVar7;
  ushort local_f8 [4];
  undefined4 local_f0;
  undefined4 local_ec;
  undefined4 local_e8;
  undefined4 local_e4;
  undefined4 local_e0;
  undefined4 local_dc;
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
  undefined2 local_b0;
  undefined2 local_ac;
  undefined2 local_aa;
  undefined2 local_a8;
  undefined2 local_a6;
  float local_a4;
  float local_a0;
  float local_9c;
  float local_98;
  undefined4 local_90;
  uint uStack_8c;
  undefined8 local_88;
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
  uVar7 = FUN_80286828();
  local_c0 = DAT_802c27e4;
  local_bc = DAT_802c27e8;
  local_b8 = DAT_802c27ec;
  local_b4 = DAT_802c27f0;
  local_b0 = DAT_802c27f4;
  local_d0 = DAT_802c27f8;
  local_cc = DAT_802c27fc;
  local_c8 = DAT_802c2800;
  local_c4 = DAT_802c2804;
  local_e0 = DAT_802c2808;
  local_dc = DAT_802c280c;
  local_d8 = DAT_802c2810;
  local_d4 = DAT_802c2814;
  local_f0 = DAT_802c2818;
  local_ec = DAT_802c281c;
  local_e8 = DAT_802c2820;
  local_e4 = DAT_802c2824;
  local_a4 = (float)extraout_f1;
  local_a6 = *(undefined2 *)((int)&local_c0 + (param_7 & 0xff) * 2);
  local_aa = 0x3c;
  iVar3 = 0;
  dVar6 = (double)(float)(param_2 - param_3);
  iVar1 = ((uint)uVar7 & 0xff) * 2;
  do {
    uVar2 = FUN_80022264(0,99);
    if ((int)uVar2 < (int)(param_9 & 0xff)) {
      uVar2 = FUN_80022264(0,0xffff);
      local_f8[0] = (ushort)uVar2;
      local_f8[1] = 0;
      local_f8[2] = 0;
      uStack_8c = FUN_80022264(1,1000);
      uStack_8c = uStack_8c ^ 0x80000000;
      local_90 = 0x43300000;
      dVar5 = (double)((float)((double)CONCAT44(0x43300000,uStack_8c) - DOUBLE_803dffe0) /
                      FLOAT_803dffe8);
      uVar2 = FUN_80022264(0,1000);
      local_88 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      dVar4 = (double)((float)(local_88 - DOUBLE_803dffe0) / FLOAT_803dffe8);
      local_9c = FLOAT_803dffdc;
      local_98 = FLOAT_803dffdc;
      switch(param_8 & 0xff) {
      case 1:
        local_a0 = -(float)(dVar5 * dVar5 - (double)FLOAT_803dffd4);
        break;
      case 2:
        dVar4 = (double)(float)(dVar4 * (double)(float)(dVar4 * dVar4));
        local_a0 = -(float)(dVar5 * dVar5 - (double)FLOAT_803dffd4);
        break;
      case 3:
        dVar4 = -(double)(float)(dVar4 * (double)(float)(dVar4 * dVar4) - (double)FLOAT_803dffd4);
        local_a0 = -(float)(dVar5 * dVar5 - (double)FLOAT_803dffd4);
        break;
      case 4:
        local_88 = (double)(longlong)(int)((double)FLOAT_803dffd0 * dVar4);
        uStack_8c = (int)((double)FLOAT_803dffd0 * dVar4) & 0xffff;
        local_90 = 0x43300000;
        dVar4 = (double)FUN_80294964();
        dVar4 = (double)(FLOAT_803dffd8 * (float)((double)FLOAT_803dffd4 + dVar4));
        local_a0 = -(float)(dVar5 * dVar5 - (double)FLOAT_803dffd4);
        break;
      case 5:
        local_88 = (double)(longlong)(int)((double)FLOAT_803dffd0 * dVar4);
        uStack_8c = (int)((double)FLOAT_803dffd0 * dVar4) & 0xffff;
        local_90 = 0x43300000;
        dVar4 = (double)FUN_802945e0();
        dVar4 = (double)(FLOAT_803dffd8 * (float)((double)FLOAT_803dffd4 + dVar4));
        local_a0 = -(float)(dVar5 * dVar5 - (double)FLOAT_803dffd4);
        break;
      case 6:
        local_a0 = (float)(dVar5 * dVar5);
        break;
      case 7:
        local_a0 = -(float)(dVar5 * (double)(float)(dVar5 * (double)(float)(dVar5 * (double)(float)(
                                                  dVar5 * dVar5))) - (double)FLOAT_803dffd4);
      }
      local_a0 = local_a0 * (float)(dVar4 * dVar6 + param_3);
      FUN_80021b8c(local_f8,&local_a0);
      local_9c = (float)((double)(float)(dVar4 - (double)FLOAT_803dffd8) * param_4);
      if (param_10 != 0) {
        local_a0 = local_a0 + *(float *)(param_10 + 0xc);
        local_9c = local_9c + *(float *)(param_10 + 0x10);
        local_98 = local_98 + *(float *)(param_10 + 0x14);
      }
      local_a8 = *(undefined2 *)((int)&local_e0 + iVar1);
      local_ac = *(undefined2 *)((int)&local_f0 + iVar1);
      (**(code **)(*DAT_803dd708 + 8))
                ((int)((ulonglong)uVar7 >> 0x20),*(undefined2 *)((int)&local_d0 + iVar1),&local_ac,
                 param_11 | 2,0xffffffff,0);
    }
    iVar3 = iVar3 + 1;
  } while (iVar3 < 4);
  FUN_80286874();
  return;
}

