// Function: FUN_80153ce8
// Entry: 80153ce8
// Size: 960 bytes

void FUN_80153ce8(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 short *param_9,int param_10)

{
  bool bVar1;
  short sVar2;
  int iVar3;
  char cVar5;
  uint uVar4;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  uint uVar6;
  double dVar7;
  undefined8 uVar8;
  undefined auStack_48 [4];
  short asStack_44 [4];
  short asStack_3c [4];
  float local_34;
  float local_30;
  float local_2c;
  float local_28;
  float local_24;
  undefined4 local_20;
  undefined4 local_18;
  uint uStack_14;
  
  *(byte *)(param_10 + 0x33b) = *(byte *)(param_10 + 0x33b) & 0x7f;
  bVar1 = false;
  iVar3 = *(int *)(param_10 + 0x29c);
  local_34 = *(float *)(param_9 + 6) - *(float *)(iVar3 + 0xc);
  local_30 = *(float *)(param_9 + 8) - *(float *)(iVar3 + 0x10);
  local_2c = *(float *)(param_9 + 10) - *(float *)(iVar3 + 0x14);
  dVar7 = FUN_80247f54(&local_34);
  if (((double)FLOAT_803e3598 <= dVar7) ||
     ((*(ushort *)(*(int *)(param_10 + 0x29c) + 0xb0) & 0x1000) != 0)) {
    cVar5 = '\0';
  }
  else {
    local_28 = *(float *)(param_9 + 6);
    local_24 = FLOAT_803e359c + *(float *)(param_9 + 8);
    local_20 = *(undefined4 *)(param_9 + 10);
    FUN_80012d20(&local_28,asStack_44);
    iVar3 = *(int *)(param_10 + 0x29c);
    local_28 = *(float *)(iVar3 + 0xc);
    local_24 = FLOAT_803e35a0 + *(float *)(iVar3 + 0x10);
    local_20 = *(undefined4 *)(iVar3 + 0x14);
    uVar8 = FUN_80012d20(&local_28,asStack_3c);
    cVar5 = FUN_800128fc(uVar8,param_2,param_3,param_4,param_5,param_6,param_7,param_8,asStack_3c,
                         asStack_44,(undefined4 *)0x0,auStack_48,0);
    if (cVar5 != '\0') {
      FUN_8014d3f4(param_9,param_10,0x14,0);
      param_2 = (double)local_2c;
      iVar3 = FUN_80021884();
      sVar2 = (short)iVar3 - *param_9;
      if (0x8000 < sVar2) {
        sVar2 = sVar2 + 1;
      }
      if (sVar2 < -0x8000) {
        sVar2 = sVar2 + -1;
      }
      if (sVar2 < 0) {
        sVar2 = -sVar2;
      }
      if (sVar2 < 1000) {
        bVar1 = true;
      }
    }
  }
  if ((*(byte *)(param_10 + 0x33b) & 0x40) == 0) {
    FUN_8000b4f0((uint)param_9,0x49b,2);
    FUN_8014d504((double)FLOAT_803e35a4,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 (int)param_9,param_10,2,0,0,in_r8,in_r9,in_r10);
    *(byte *)(param_10 + 0x33b) = *(byte *)(param_10 + 0x33b) | 0x40;
    *(undefined *)(param_10 + 0x33a) = 0;
  }
  else if ((*(uint *)(param_10 + 0x2dc) & 0x40000000) != 0) {
    if (cVar5 == '\0') {
      uVar6 = FUN_80022264(2,4);
      uVar6 = uVar6 & 0xff;
      if (uVar6 == 2) {
        uVar6 = 0;
      }
      else if (uVar6 == 4) {
        FUN_8000bb38((uint)param_9,0x357);
      }
    }
    else if (*(char *)(param_10 + 0x33a) == '\0') {
      if ((param_9[0x50] == 5) || (!bVar1)) {
        uVar6 = 4;
        uVar4 = FUN_80022264(1,2);
        *(char *)(param_10 + 0x33a) = (char)uVar4;
      }
      else {
        uVar6 = 5;
        *(undefined *)(param_10 + 0x33a) = (&DAT_803dc928)[*(byte *)(param_10 + 0x33b) & 3];
        *(byte *)(param_10 + 0x33b) = *(char *)(param_10 + 0x33b) + 1U & 0xc3;
      }
    }
    else {
      *(char *)(param_10 + 0x33a) = *(char *)(param_10 + 0x33a) + -1;
      uVar6 = (int)param_9[0x50] & 0xff;
    }
    FUN_8014d504((double)FLOAT_803e35a8,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 (int)param_9,param_10,uVar6,0,0,in_r8,in_r9,in_r10);
  }
  if (param_9[0x50] == 5) {
    dVar7 = (double)*(float *)(param_9 + 0x4c);
    if ((DOUBLE_803e35b0 <= dVar7) &&
       (dVar7 < DOUBLE_803e35b0 +
                (double)(float)((double)*(float *)(param_10 + 0x308) * (double)FLOAT_803dc074))) {
      FUN_80153aec((double)*(float *)(param_10 + 0x308),DOUBLE_803e35b0,dVar7,param_4,param_5,
                   param_6,param_7,param_8,(uint)param_9,param_10);
      goto LAB_8015407c;
    }
  }
  *(float *)(param_10 + 0x324) = *(float *)(param_10 + 0x324) - FLOAT_803dc074;
  if (*(float *)(param_10 + 0x324) <= FLOAT_803e35b8) {
    uStack_14 = FUN_80022264(0x96,300);
    uStack_14 = uStack_14 ^ 0x80000000;
    local_18 = 0x43300000;
    *(float *)(param_10 + 0x324) = (float)((double)CONCAT44(0x43300000,uStack_14) - DOUBLE_803e3590)
    ;
    FUN_8000bb38((uint)param_9,0x245);
  }
LAB_8015407c:
  FUN_80153a08((int)param_9,param_10);
  return;
}

