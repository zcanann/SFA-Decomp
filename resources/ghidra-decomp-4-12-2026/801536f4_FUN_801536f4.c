// Function: FUN_801536f4
// Entry: 801536f4
// Size: 656 bytes

void FUN_801536f4(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 ushort *param_9,undefined4 *param_10)

{
  float fVar1;
  uint uVar2;
  int iVar3;
  char cVar4;
  float *pfVar5;
  undefined8 uVar6;
  undefined auStack_48 [4];
  short asStack_44 [4];
  short asStack_3c [4];
  float local_34;
  float local_30;
  float local_2c;
  float local_28;
  float local_24;
  float local_20;
  
  pfVar5 = (float *)*param_10;
  if (*(char *)((int)param_10 + 0x33b) != '\0') {
    param_10[0xba] = param_10[0xba] | 0x80;
  }
  if ((param_10[0xb7] & 0x80000000) != 0) {
    FUN_8000bb38((uint)param_9,0x25a);
  }
  if ((((param_10[0xb7] & 0x2000) != 0) &&
      (((iVar3 = FUN_80010340((double)(FLOAT_803e356c * (float)param_10[0xbf]),pfVar5), iVar3 != 0
        || (pfVar5[4] != 0.0)) &&
       (cVar4 = (**(code **)(*DAT_803dd71c + 0x90))(pfVar5), cVar4 != '\0')))) &&
     (cVar4 = (**(code **)(*DAT_803dd71c + 0x8c))
                        ((double)FLOAT_803e3550,*param_10,param_9,&DAT_803dc920,0xffffffff),
     cVar4 != '\0')) {
    param_10[0xb7] = param_10[0xb7] & 0xffffdfff;
  }
  FUN_80035eec((int)param_9,0xe,1,0);
  iVar3 = param_10[0xa7];
  local_28 = *(float *)(iVar3 + 0xc) - *(float *)(param_9 + 6);
  local_24 = (FLOAT_803e3570 + *(float *)(iVar3 + 0x10)) - *(float *)(param_9 + 8);
  local_20 = *(float *)(iVar3 + 0x14) - *(float *)(param_9 + 10);
  FUN_80247f54(&local_28);
  param_10[0xcb] = (float)param_10[0xcb] + FLOAT_803dc074;
  if ((param_10[0xd0] != 0) || (FLOAT_803e3560 < (float)param_10[0xcb])) {
    param_10[0xb9] = param_10[0xb9] | 0x10000;
    fVar1 = FLOAT_803e3548;
    param_10[0xc9] = FLOAT_803e3548;
    param_10[0xcb] = fVar1;
  }
  else {
    local_34 = *(float *)(param_9 + 6);
    local_30 = *(float *)(param_9 + 8);
    local_2c = *(float *)(param_9 + 10);
    FUN_80012d20(&local_34,asStack_44);
    local_34 = pfVar5[0x1a];
    local_30 = pfVar5[0x1b];
    local_2c = pfVar5[0x1c];
    uVar6 = FUN_80012d20(&local_34,asStack_3c);
    uVar2 = countLeadingZeros(param_10[0xb7]);
    if (((uVar2 >> 5 & 0x1000000) != 0) &&
       (iVar3 = FUN_800128fc(uVar6,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                             asStack_3c,asStack_44,(undefined4 *)0x0,auStack_48,0), iVar3 == 0)) {
      param_10[0xb9] = param_10[0xb9] | 0x10000;
      fVar1 = FLOAT_803e3548;
      param_10[0xc9] = FLOAT_803e3548;
      param_10[0xcb] = fVar1;
    }
  }
  FUN_8014caf0((double)FLOAT_803e3554,(double)FLOAT_803e3558,(double)FLOAT_803e355c,(int)param_9,
               (int)param_10,&local_28,'\x01');
  FUN_8014d194((double)FLOAT_803e3564,(double)FLOAT_803e3568,param_9,(int)param_10,0xf,'\0');
  return;
}

