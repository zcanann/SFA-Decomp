// Function: FUN_801430b4
// Entry: 801430b4
// Size: 388 bytes

bool FUN_801430b4(undefined8 param_1,undefined8 param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9,int *param_10,undefined4 param_11,undefined4 param_12,byte param_13,
                 uint param_14,undefined4 param_15,undefined4 param_16)

{
  int iVar1;
  bool bVar2;
  char cVar3;
  int iVar4;
  undefined4 *puVar5;
  undefined4 local_28;
  undefined4 local_24;
  undefined4 local_20;
  undefined4 local_1c;
  undefined4 local_18;
  
  puVar5 = &DAT_802c295c;
  local_28 = DAT_802c295c;
  local_24 = DAT_802c2960;
  local_20 = DAT_802c2964;
  local_1c = DAT_802c2968;
  local_18 = DAT_802c296c;
  iVar1 = FUN_80144994(param_9,param_10);
  if (iVar1 != 0) {
    param_10[0x1c8] = (int)FLOAT_803e306c;
    param_10[0x15] = param_10[0x15] & 0xffffffef;
    *(undefined *)((int)param_10 + 10) = 0;
    return true;
  }
  iVar4 = *DAT_803dd6e8;
  iVar1 = (**(code **)(iVar4 + 0x24))(&local_28,5);
  if (iVar1 != 2) {
    if (iVar1 < 2) {
      if (iVar1 < 0) goto LAB_801431cc;
    }
    else if (5 < iVar1) goto LAB_801431cc;
    iVar1 = *(int *)(param_9 + 0xb8);
    if (((*(byte *)(iVar1 + 0x58) >> 6 & 1) == 0) &&
       (((0x2f < *(short *)(param_9 + 0xa0) || (*(short *)(param_9 + 0xa0) < 0x29)) &&
        (bVar2 = FUN_8000b598(param_9,0x10), !bVar2)))) {
      iVar4 = 0x35d;
      puVar5 = (undefined4 *)0x500;
      param_13 = 0xff;
      param_14 = 0;
      FUN_800394f0(param_9,iVar1 + 0x3a8,0x35d,0x500,0xffffffff,0);
    }
  }
LAB_801431cc:
  if (FLOAT_803e306c == (float)param_10[0x1c8]) {
    param_10[0x15] = param_10[0x15] & 0xffffffef;
    *(undefined *)((int)param_10 + 10) = 0;
  }
  cVar3 = FUN_8013b6f0((double)FLOAT_803e3098,param_2,param_3,param_4,param_5,param_6,param_7,
                       param_8,param_9,param_10,iVar4,puVar5,param_13,param_14,param_15,param_16);
  return cVar3 == '\x01';
}

