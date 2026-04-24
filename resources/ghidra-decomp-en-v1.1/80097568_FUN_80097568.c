// Function: FUN_80097568
// Entry: 80097568
// Size: 1112 bytes

/* WARNING: Removing unreachable block (ram,0x800979a0) */
/* WARNING: Removing unreachable block (ram,0x80097998) */
/* WARNING: Removing unreachable block (ram,0x80097580) */
/* WARNING: Removing unreachable block (ram,0x80097578) */

void FUN_80097568(undefined8 param_1,double param_2,undefined4 param_3,undefined4 param_4,
                 uint param_5,uint param_6,uint param_7,int param_8,uint param_9)

{
  int iVar1;
  uint uVar2;
  int iVar3;
  double extraout_f1;
  double in_f30;
  double dVar4;
  double in_f31;
  double in_ps30_1;
  double in_ps31_1;
  undefined8 uVar5;
  ushort local_c8;
  undefined2 local_c6;
  undefined2 local_c4;
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
  undefined4 local_98;
  undefined4 local_94;
  undefined4 local_90;
  undefined4 local_8c;
  undefined4 local_88;
  undefined4 local_84;
  undefined2 local_80;
  undefined2 local_7c;
  undefined2 local_7a;
  undefined2 local_78;
  undefined2 local_76;
  float local_74;
  float local_70;
  float local_6c;
  float local_68;
  undefined4 local_60;
  uint uStack_5c;
  float local_18;
  float fStack_14;
  float local_8;
  float fStack_4;
  
  local_8 = (float)in_f31;
  fStack_4 = (float)in_ps31_1;
  local_18 = (float)in_f30;
  fStack_14 = (float)in_ps30_1;
  uVar5 = FUN_80286828();
  local_90 = DAT_802c2828;
  local_8c = DAT_802c282c;
  local_88 = DAT_802c2830;
  local_84 = DAT_802c2834;
  local_80 = DAT_802c2838;
  local_a0 = DAT_802c283c;
  local_9c = DAT_802c2840;
  local_98 = DAT_802c2844;
  local_94 = DAT_802c2848;
  local_b0 = DAT_802c284c;
  local_ac = DAT_802c2850;
  local_a8 = DAT_802c2854;
  local_a4 = DAT_802c2858;
  local_c0 = DAT_802c285c;
  local_bc = DAT_802c2860;
  local_b8 = DAT_802c2864;
  local_b4 = DAT_802c2868;
  local_74 = (float)extraout_f1;
  local_76 = *(undefined2 *)((int)&local_90 + (param_5 & 0xff) * 2);
  local_7a = 0x3c;
  iVar3 = 0;
  iVar1 = ((uint)uVar5 & 0xff) * 2;
  do {
    uVar2 = FUN_80022264(0,99);
    if ((int)uVar2 < (int)(param_7 & 0xff)) {
      uStack_5c = FUN_80022264(0,1000);
      uStack_5c = uStack_5c ^ 0x80000000;
      local_60 = 0x43300000;
      dVar4 = (double)((float)((double)CONCAT44(0x43300000,uStack_5c) - DOUBLE_803dffe0) /
                      FLOAT_803dffe8);
      switch(param_6 & 0xff) {
      case 1:
        uVar2 = FUN_80022264(0,0xffff);
        local_c8 = (ushort)uVar2;
        uVar2 = FUN_80022264(0,0xffff);
        local_c6 = (undefined2)uVar2;
        uVar2 = FUN_80022264(0,0xffff);
        local_c4 = (undefined2)uVar2;
        local_70 = (float)(param_2 *
                          -(double)(float)(dVar4 * (double)(float)(dVar4 * dVar4) -
                                          (double)FLOAT_803dffd4));
        break;
      case 2:
        local_c8 = 0;
        uVar2 = FUN_80022264(0,0xffff);
        local_c6 = (undefined2)uVar2;
        local_c4 = 0;
        local_70 = (float)(param_2 *
                          -(double)(float)(dVar4 * (double)(float)(dVar4 * dVar4) -
                                          (double)FLOAT_803dffd4));
        break;
      case 3:
        uVar2 = FUN_80022264(0,0xffff);
        local_c8 = (ushort)uVar2;
        local_c6 = 0;
        local_c4 = 0;
        local_70 = (float)(param_2 *
                          -(double)(float)(dVar4 * (double)(float)(dVar4 * dVar4) -
                                          (double)FLOAT_803dffd4));
        break;
      case 4:
        local_c8 = 0;
        local_c6 = 0;
        uVar2 = FUN_80022264(0,0xffff);
        local_c4 = (undefined2)uVar2;
        local_70 = (float)(param_2 *
                          -(double)(float)(dVar4 * (double)(float)(dVar4 * dVar4) -
                                          (double)FLOAT_803dffd4));
        break;
      case 5:
        uVar2 = FUN_80022264(0x7fff,0xffff);
        local_c8 = (ushort)uVar2;
        local_c6 = 0;
        uVar2 = FUN_80022264(0,0xffff);
        local_c4 = (undefined2)uVar2;
        local_70 = (float)(param_2 *
                          -(double)(float)(dVar4 * (double)(float)(dVar4 * dVar4) -
                                          (double)FLOAT_803dffd4));
        break;
      case 6:
        uVar2 = FUN_80022264(0,0xffff);
        local_c8 = (ushort)uVar2;
        uVar2 = FUN_80022264(0,0xffff);
        local_c6 = (undefined2)uVar2;
        uVar2 = FUN_80022264(0,0xffff);
        local_c4 = (undefined2)uVar2;
        local_70 = (float)(dVar4 * param_2);
        break;
      case 7:
        uVar2 = FUN_80022264(0,0xffff);
        local_c8 = (ushort)uVar2;
        uVar2 = FUN_80022264(0,0xffff);
        local_c6 = (undefined2)uVar2;
        uVar2 = FUN_80022264(0,0xffff);
        local_c4 = (undefined2)uVar2;
        local_70 = (float)(param_2 *
                          -(double)(float)(dVar4 * (double)(float)(dVar4 * (double)(float)(dVar4 * (
                                                  double)(float)(dVar4 * dVar4))) -
                                          (double)FLOAT_803dffd4));
      }
      local_6c = FLOAT_803dffdc;
      local_68 = FLOAT_803dffdc;
      FUN_80021b8c(&local_c8,&local_70);
      if (param_8 != 0) {
        local_70 = local_70 + *(float *)(param_8 + 0xc);
        local_6c = local_6c + *(float *)(param_8 + 0x10);
        local_68 = local_68 + *(float *)(param_8 + 0x14);
      }
      local_78 = *(undefined2 *)((int)&local_b0 + iVar1);
      local_7c = *(undefined2 *)((int)&local_c0 + iVar1);
      (**(code **)(*DAT_803dd708 + 8))
                ((int)((ulonglong)uVar5 >> 0x20),*(undefined2 *)((int)&local_a0 + iVar1),&local_7c,
                 param_9 | 2,0xffffffff,0);
    }
    iVar3 = iVar3 + 1;
  } while (iVar3 < 4);
  FUN_80286874();
  return;
}

