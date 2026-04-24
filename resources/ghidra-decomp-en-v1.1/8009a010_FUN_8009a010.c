// Function: FUN_8009a010
// Entry: 8009a010
// Size: 1112 bytes

/* WARNING: Removing unreachable block (ram,0x8009a448) */
/* WARNING: Removing unreachable block (ram,0x8009a440) */
/* WARNING: Removing unreachable block (ram,0x8009a028) */
/* WARNING: Removing unreachable block (ram,0x8009a020) */

void FUN_8009a010(undefined8 param_1,double param_2,undefined4 param_3,undefined4 param_4,
                 int *param_5)

{
  int iVar1;
  double extraout_f1;
  double in_f30;
  double dVar2;
  double in_f31;
  double dVar3;
  double in_ps30_1;
  double in_ps31_1;
  undefined8 uVar4;
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
  uint uStack_54;
  undefined4 local_50;
  uint uStack_4c;
  undefined4 local_48;
  uint uStack_44;
  float local_18;
  float fStack_14;
  float local_8;
  float fStack_4;
  
  local_8 = (float)in_f31;
  fStack_4 = (float)in_ps31_1;
  local_18 = (float)in_f30;
  fStack_14 = (float)in_ps30_1;
  uVar4 = FUN_80286840();
  iVar1 = (int)((ulonglong)uVar4 >> 0x20);
  local_98 = (float)param_2;
  dVar3 = (double)FLOAT_803e0014;
  local_94 = DAT_802c2758;
  local_90 = DAT_802c275c;
  local_8c = DAT_802c2760;
  local_88 = DAT_802c2764;
  local_84 = DAT_802c2768;
  local_80 = DAT_802c276c;
  local_7c = DAT_802c2770;
  local_78 = DAT_802c2774;
  local_6c = (float)extraout_f1;
  local_74 = 0;
  local_70 = 0;
  local_72 = 0;
  local_6e = 0xc0a;
  switch((uint)uVar4 & 0xff) {
  case 1:
    dVar2 = extraout_f1;
    uStack_54 = FUN_80022264(0xfffffff6,10);
    uStack_54 = uStack_54 ^ 0x80000000;
    local_58 = 0x43300000;
    local_68 = (float)(dVar2 * (double)(float)((double)CONCAT44(0x43300000,uStack_54) -
                                              DOUBLE_803dffe0));
    uStack_4c = FUN_80022264(0xfffffff6,10);
    uStack_4c = uStack_4c ^ 0x80000000;
    local_50 = 0x43300000;
    local_64 = (float)(dVar2 * (double)(float)((double)CONCAT44(0x43300000,uStack_4c) -
                                              DOUBLE_803dffe0));
    uStack_44 = FUN_80022264(0xfffffff6,10);
    uStack_44 = uStack_44 ^ 0x80000000;
    local_48 = 0x43300000;
    local_60 = (float)(dVar2 * (double)(float)((double)CONCAT44(0x43300000,uStack_44) -
                                              DOUBLE_803dffe0));
    (**(code **)(*DAT_803dd708 + 8))(iVar1,0x32f,&local_74,2,0xffffffff,&local_98);
    break;
  case 2:
    dVar2 = extraout_f1;
    uStack_44 = FUN_80022264(0xfffffff6,10);
    uStack_44 = uStack_44 ^ 0x80000000;
    local_48 = 0x43300000;
    local_68 = (float)(dVar2 * (double)(float)((double)CONCAT44(0x43300000,uStack_44) -
                                              DOUBLE_803dffe0));
    uStack_4c = FUN_80022264(0xfffffff6,10);
    uStack_4c = uStack_4c ^ 0x80000000;
    local_50 = 0x43300000;
    local_64 = (float)(dVar2 * (double)(float)((double)CONCAT44(0x43300000,uStack_4c) -
                                              DOUBLE_803dffe0));
    uStack_54 = FUN_80022264(0xfffffff6,10);
    uStack_54 = uStack_54 ^ 0x80000000;
    local_58 = 0x43300000;
    local_60 = (float)(dVar2 * (double)(float)((double)CONCAT44(0x43300000,uStack_54) -
                                              DOUBLE_803dffe0));
    (**(code **)(*DAT_803dd708 + 8))(iVar1,0x330,&local_74,2,0xffffffff,&local_98);
    break;
  case 3:
    (**(code **)(*DAT_803dd734 + 0xc))(iVar1,0x32f,&local_98,0x19,0);
    break;
  case 4:
    (**(code **)(*DAT_803dd734 + 0xc))(iVar1,0x330,&local_98,0x19,0);
    break;
  case 5:
    local_6e = 0xc0a;
    (**(code **)(*DAT_803dd734 + 0xc))(iVar1,0x7cd,&local_98,0x32,&local_74);
    break;
  case 6:
    local_6e = 0xc0d;
    (**(code **)(*DAT_803dd734 + 0xc))(iVar1,0x7ce,&local_98,0x50,&local_74);
    break;
  case 7:
    local_6e = 0x605;
    local_70 = 1;
    (**(code **)(*DAT_803dd734 + 0xc))(iVar1,1999,&local_98,0x19,&local_74);
    dVar3 = (double)FLOAT_803dffdc;
    break;
  case 8:
    local_6e = 0x605;
    local_70 = 0;
    (**(code **)(*DAT_803dd734 + 0xc))(iVar1,1999,&local_98,0x19,&local_74);
    dVar3 = (double)FLOAT_803dffdc;
  }
  if (param_5 != (int *)0x0) {
    FUN_8001dbf0((int)param_5,2);
    FUN_8001de4c((double)*(float *)(iVar1 + 0x18),
                 (double)(float)((double)*(float *)(iVar1 + 0x1c) + dVar3),
                 (double)*(float *)(iVar1 + 0x20),param_5);
    iVar1 = ((uint)uVar4 & 0xff) * 3;
    FUN_8001dbb4((int)param_5,*(undefined *)((int)&local_94 + iVar1),
                 *(undefined *)((int)&local_94 + iVar1 + 1),
                 *(undefined *)((int)&local_94 + iVar1 + 2),0xff);
    FUN_8001dadc((int)param_5,*(undefined *)((int)&local_94 + iVar1),
                 *(undefined *)((int)&local_94 + iVar1 + 1),
                 *(undefined *)((int)&local_94 + iVar1 + 2),0xff);
    FUN_8001dcfc((double)FLOAT_803dffcc,(double)FLOAT_803e0018,(int)param_5);
    FUN_8001dc18((int)param_5,0);
    FUN_8001dc30((double)FLOAT_803dffdc,(int)param_5,'\x01');
    FUN_8001dc30((double)FLOAT_803dffd4,(int)param_5,'\0');
    FUN_8001d6e4((int)param_5,0,0);
    FUN_8001de04((int)param_5,1);
  }
  FUN_8028688c();
  return;
}

