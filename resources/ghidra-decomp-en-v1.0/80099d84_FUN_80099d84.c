// Function: FUN_80099d84
// Entry: 80099d84
// Size: 1112 bytes

/* WARNING: Removing unreachable block (ram,0x8009a1b4) */
/* WARNING: Removing unreachable block (ram,0x8009a1bc) */

void FUN_80099d84(undefined8 param_1,double param_2,undefined4 param_3,undefined4 param_4,
                 int param_5)

{
  int iVar1;
  undefined4 uVar2;
  double extraout_f1;
  undefined8 in_f30;
  double dVar3;
  undefined8 in_f31;
  double dVar4;
  undefined8 uVar5;
  float local_98;
  undefined4 local_94;
  undefined4 local_90;
  undefined4 local_8c;
  undefined4 local_88;
  undefined4 local_84;
  undefined4 local_80;
  undefined4 local_7c;
  undefined2 local_78;
  undefined2 local_74;
  undefined2 local_72;
  undefined2 local_70;
  undefined2 local_6e;
  float local_6c;
  float local_68;
  float local_64;
  float local_60;
  undefined4 local_58;
  uint uStack84;
  undefined4 local_50;
  uint uStack76;
  undefined4 local_48;
  uint uStack68;
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar2 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  __psq_st0(auStack24,(int)((ulonglong)in_f30 >> 0x20),0);
  __psq_st1(auStack24,(int)in_f30,0);
  uVar5 = FUN_802860dc();
  iVar1 = (int)((ulonglong)uVar5 >> 0x20);
  local_98 = (float)param_2;
  dVar4 = (double)FLOAT_803df394;
  local_94 = DAT_802c1fd8;
  local_90 = DAT_802c1fdc;
  local_8c = DAT_802c1fe0;
  local_88 = DAT_802c1fe4;
  local_84 = DAT_802c1fe8;
  local_80 = DAT_802c1fec;
  local_7c = DAT_802c1ff0;
  local_78 = DAT_802c1ff4;
  local_6c = (float)extraout_f1;
  local_74 = 0;
  local_70 = 0;
  local_72 = 0;
  local_6e = 0xc0a;
  switch((uint)uVar5 & 0xff) {
  case 1:
    dVar3 = extraout_f1;
    uStack84 = FUN_800221a0(0xfffffff6,10);
    uStack84 = uStack84 ^ 0x80000000;
    local_58 = 0x43300000;
    local_68 = (float)(dVar3 * (double)(float)((double)CONCAT44(0x43300000,uStack84) -
                                              DOUBLE_803df360));
    uStack76 = FUN_800221a0(0xfffffff6,10);
    uStack76 = uStack76 ^ 0x80000000;
    local_50 = 0x43300000;
    local_64 = (float)(dVar3 * (double)(float)((double)CONCAT44(0x43300000,uStack76) -
                                              DOUBLE_803df360));
    uStack68 = FUN_800221a0(0xfffffff6,10);
    uStack68 = uStack68 ^ 0x80000000;
    local_48 = 0x43300000;
    local_60 = (float)(dVar3 * (double)(float)((double)CONCAT44(0x43300000,uStack68) -
                                              DOUBLE_803df360));
    (**(code **)(*DAT_803dca88 + 8))(iVar1,0x32f,&local_74,2,0xffffffff,&local_98);
    break;
  case 2:
    dVar3 = extraout_f1;
    uStack68 = FUN_800221a0(0xfffffff6,10);
    uStack68 = uStack68 ^ 0x80000000;
    local_48 = 0x43300000;
    local_68 = (float)(dVar3 * (double)(float)((double)CONCAT44(0x43300000,uStack68) -
                                              DOUBLE_803df360));
    uStack76 = FUN_800221a0(0xfffffff6,10);
    uStack76 = uStack76 ^ 0x80000000;
    local_50 = 0x43300000;
    local_64 = (float)(dVar3 * (double)(float)((double)CONCAT44(0x43300000,uStack76) -
                                              DOUBLE_803df360));
    uStack84 = FUN_800221a0(0xfffffff6,10);
    uStack84 = uStack84 ^ 0x80000000;
    local_58 = 0x43300000;
    local_60 = (float)(dVar3 * (double)(float)((double)CONCAT44(0x43300000,uStack84) -
                                              DOUBLE_803df360));
    (**(code **)(*DAT_803dca88 + 8))(iVar1,0x330,&local_74,2,0xffffffff,&local_98);
    break;
  case 3:
    (**(code **)(*DAT_803dcab4 + 0xc))(iVar1,0x32f,&local_98,0x19,0);
    break;
  case 4:
    (**(code **)(*DAT_803dcab4 + 0xc))(iVar1,0x330,&local_98,0x19,0);
    break;
  case 5:
    local_6e = 0xc0a;
    (**(code **)(*DAT_803dcab4 + 0xc))(iVar1,0x7cd,&local_98,0x32,&local_74);
    break;
  case 6:
    local_6e = 0xc0d;
    (**(code **)(*DAT_803dcab4 + 0xc))(iVar1,0x7ce,&local_98,0x50,&local_74);
    break;
  case 7:
    local_6e = 0x605;
    local_70 = 1;
    (**(code **)(*DAT_803dcab4 + 0xc))(iVar1,1999,&local_98,0x19,&local_74);
    dVar4 = (double)FLOAT_803df35c;
    break;
  case 8:
    local_6e = 0x605;
    local_70 = 0;
    (**(code **)(*DAT_803dcab4 + 0xc))(iVar1,1999,&local_98,0x19,&local_74);
    dVar4 = (double)FLOAT_803df35c;
  }
  if (param_5 != 0) {
    FUN_8001db2c(param_5,2);
    FUN_8001dd88((double)*(float *)(iVar1 + 0x18),
                 (double)(float)((double)*(float *)(iVar1 + 0x1c) + dVar4),
                 (double)*(float *)(iVar1 + 0x20),param_5);
    iVar1 = ((uint)uVar5 & 0xff) * 3;
    FUN_8001daf0(param_5,*(undefined *)((int)&local_94 + iVar1),
                 *(undefined *)((int)&local_94 + iVar1 + 1),
                 *(undefined *)((int)&local_94 + iVar1 + 2),0xff);
    FUN_8001da18(param_5,*(undefined *)((int)&local_94 + iVar1),
                 *(undefined *)((int)&local_94 + iVar1 + 1),
                 *(undefined *)((int)&local_94 + iVar1 + 2),0xff);
    FUN_8001dc38((double)FLOAT_803df34c,(double)FLOAT_803df398,param_5);
    FUN_8001db54(param_5,0);
    FUN_8001db6c((double)FLOAT_803df35c,param_5,1);
    FUN_8001db6c((double)FLOAT_803df354,param_5,0);
    FUN_8001d620(param_5,0,0);
    FUN_8001dd40(param_5,1);
  }
  __psq_l0(auStack8,uVar2);
  __psq_l1(auStack8,uVar2);
  __psq_l0(auStack24,uVar2);
  __psq_l1(auStack24,uVar2);
  FUN_80286128();
  return;
}

