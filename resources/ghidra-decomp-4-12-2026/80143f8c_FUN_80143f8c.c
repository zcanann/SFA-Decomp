// Function: FUN_80143f8c
// Entry: 80143f8c
// Size: 464 bytes

undefined4
FUN_80143f8c(undefined8 param_1,undefined8 param_2,double param_3,undefined8 param_4,
            undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,int param_9,
            int *param_10,int param_11,undefined4 param_12,byte param_13,uint param_14,
            undefined4 param_15,undefined4 param_16)

{
  float fVar1;
  char cVar3;
  bool bVar4;
  undefined4 uVar2;
  int iVar5;
  
  param_10[9] = param_10[1];
  if (param_10[10] != param_10[9] + 0x18) {
    param_10[10] = param_10[9] + 0x18;
    param_10[0x15] = param_10[0x15] & 0xfffffbff;
    *(undefined2 *)((int)param_10 + 0xd2) = 0;
  }
  if (FLOAT_803e306c == (float)param_10[0x1c7]) {
    *(undefined *)((int)param_10 + 0xd) = 0xff;
    fVar1 = FLOAT_803e3158;
  }
  else {
    fVar1 = FLOAT_803e3098;
    if ((param_10[0x15] & 0x20000U) != 0) {
      *(undefined *)((int)param_10 + 0xd) = 0;
      param_10[0x15] = param_10[0x15] & 0xfffdffff;
      fVar1 = FLOAT_803e3098;
    }
  }
  cVar3 = FUN_8013b6f0((double)fVar1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9
                       ,param_10,param_11,param_12,param_13,param_14,param_15,param_16);
  if (cVar3 == '\x01') {
    *(byte *)(param_10 + 0x1ca) = *(byte *)(param_10 + 0x1ca) & 0x7f | 0x80;
    uVar2 = 1;
  }
  else {
    if ((((cVar3 == '\x02') && ((param_10[0x15] & 2U) != 0)) &&
        (iVar5 = *(int *)(param_9 + 0xb8), (*(byte *)(iVar5 + 0x58) >> 6 & 1) == 0)) &&
       (((0x2f < *(short *)(param_9 + 0xa0) || (*(short *)(param_9 + 0xa0) < 0x29)) &&
        (bVar4 = FUN_8000b598(param_9,0x10), !bVar4)))) {
      FUN_800394f0(param_9,iVar5 + 0x3a8,0x35d,0x500,0xffffffff,0);
    }
    if (FLOAT_803e306c == (float)param_10[0xab]) {
      bVar4 = false;
    }
    else if (FLOAT_803e30a0 == (float)param_10[0xac]) {
      bVar4 = true;
    }
    else if ((float)param_10[0xad] - (float)param_10[0xac] <= FLOAT_803e30a4) {
      bVar4 = false;
    }
    else {
      bVar4 = true;
    }
    if (bVar4) {
      uVar2 = 0;
    }
    else {
      uVar2 = FUN_8014415c(param_9,param_10);
    }
  }
  return uVar2;
}

