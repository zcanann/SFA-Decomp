// Function: FUN_801e9764
// Entry: 801e9764
// Size: 500 bytes

void FUN_801e9764(short *param_1,int param_2)

{
  char cVar1;
  int iVar2;
  uint uVar3;
  float *pfVar4;
  double dVar5;
  undefined2 local_38;
  undefined local_36;
  undefined4 local_30;
  uint uStack_2c;
  undefined4 local_28;
  uint uStack_24;
  undefined4 local_20;
  uint uStack_1c;
  undefined4 local_18;
  uint uStack_14;
  
  pfVar4 = *(float **)(param_1 + 0x5c);
  local_38 = DAT_803e6708;
  local_36 = DAT_803e670a;
  param_1[0x58] = param_1[0x58] | 0x6000;
  *param_1 = (short)((int)*(char *)(param_2 + 0x18) << 8);
  uStack_2c = (int)*param_1 ^ 0x80000000;
  local_30 = 0x43300000;
  dVar5 = (double)FUN_802945e0();
  *(float *)(param_1 + 0x12) = (float)-dVar5;
  uStack_24 = (int)*param_1 ^ 0x80000000;
  local_28 = 0x43300000;
  dVar5 = (double)FUN_80294964();
  *(float *)(param_1 + 0x16) = (float)-dVar5;
  *(char *)((int)param_1 + 0xad) = '\x01' - *(char *)(param_2 + 0x19);
  uStack_1c = (int)*(short *)(param_2 + 0x1a) ^ 0x80000000;
  local_20 = 0x43300000;
  *pfVar4 = (float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803e6730);
  uStack_14 = FUN_80022264(0,100);
  uStack_14 = uStack_14 ^ 0x80000000;
  local_18 = 0x43300000;
  pfVar4[1] = FLOAT_803e672c +
              (float)((double)CONCAT44(0x43300000,uStack_14) - DOUBLE_803e6730) / FLOAT_803e6718;
  pfVar4[2] = *(float *)(param_2 + 0x14);
  *(undefined4 *)(param_2 + 0x14) = 0xffffffff;
  FUN_8000dcdc((uint)param_1,0x406);
  iVar2 = FUN_8002b660((int)param_1);
  cVar1 = *(char *)(param_2 + 0x19);
  if (cVar1 == '\x01') {
    *(undefined2 *)(pfVar4 + 3) = 0x42;
    *(undefined2 *)((int)pfVar4 + 0xe) = 1;
    *(undefined2 *)(pfVar4 + 4) = 0;
  }
  else if ((cVar1 < '\x01') && (-1 < cVar1)) {
    uVar3 = FUN_80022264(0,2);
    *(undefined *)(*(int *)(iVar2 + 0x34) + 8) = *(undefined *)((int)&local_38 + uVar3);
    *(undefined2 *)(pfVar4 + 3) = 0x41;
    *(undefined2 *)((int)pfVar4 + 0xe) = 4;
    *(undefined2 *)(pfVar4 + 4) = 2;
  }
  return;
}

