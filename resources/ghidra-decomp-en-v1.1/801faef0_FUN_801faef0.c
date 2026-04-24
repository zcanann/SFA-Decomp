// Function: FUN_801faef0
// Entry: 801faef0
// Size: 772 bytes

void FUN_801faef0(short *param_1)

{
  short sVar1;
  int iVar2;
  uint uVar3;
  ushort uVar4;
  short *psVar5;
  int iVar6;
  int local_28 [2];
  undefined8 local_20;
  
  iVar6 = *(int *)(param_1 + 0x26);
  psVar5 = *(short **)(param_1 + 0x5c);
  local_28[0] = 0;
  if (*(char *)((int)psVar5 + 5) == '\0') {
    *(undefined *)((int)psVar5 + 9) = 5;
    *(undefined *)((int)psVar5 + 0xb) = 0x28;
    *(undefined *)(psVar5 + 5) = 5;
  }
  else {
    *(undefined *)((int)psVar5 + 9) = 6;
    *(undefined *)((int)psVar5 + 0xb) = 0x14;
    *(undefined *)(psVar5 + 5) = 10;
  }
  psVar5[1] = psVar5[1] - (short)(int)FLOAT_803dc074;
  sVar1 = *(short *)(iVar6 + 0x1a);
  if (sVar1 == 0) {
    local_20 = (double)CONCAT44(0x43300000,(uint)*(byte *)(psVar5 + 5));
    FUN_80097568((double)FLOAT_803e6d50,(double)(float)(local_20 - DOUBLE_803e6d58),param_1,
                 (uint)*(byte *)((int)psVar5 + 9),5,1,(uint)*(byte *)((int)psVar5 + 0xb),0,0);
  }
  else if (sVar1 == 1) {
    local_20 = (double)CONCAT44(0x43300000,(uint)*(byte *)(psVar5 + 5));
    FUN_80097568((double)FLOAT_803e6d50,(double)(float)(local_20 - DOUBLE_803e6d58),param_1,
                 (uint)*(byte *)((int)psVar5 + 9),2,1,(uint)*(byte *)((int)psVar5 + 0xb),0,0);
  }
  else {
    local_20 = (double)CONCAT44(0x43300000,(uint)*(byte *)(psVar5 + 5));
    FUN_80097568((double)FLOAT_803e6d50,(double)(float)(local_20 - DOUBLE_803e6d58),param_1,
                 (uint)*(byte *)((int)psVar5 + 9),1,1,(uint)*(byte *)((int)psVar5 + 0xb),0,0);
  }
  iVar2 = FUN_8002bac4();
  FUN_800217c8((float *)(iVar2 + 0x18),(float *)(param_1 + 0xc));
  *(undefined *)((int)psVar5 + 7) = *(undefined *)((int)psVar5 + 5);
  uVar3 = FUN_80020078((int)*psVar5);
  if (uVar3 == 0) {
    iVar2 = FUN_80036974((int)param_1,local_28,(int *)0x0,(uint *)0x0);
    if ((((local_28[0] != 0) && (iVar2 != 0)) && (local_28[0] != 0)) &&
       (*(short *)(local_28[0] + 0x46) == 0x14b)) {
      uVar4 = FUN_8016f618(local_28[0]);
      if (*(ushort *)(iVar6 + 0x1a) == (uVar4 & 0xff)) {
        *(char *)((int)psVar5 + 5) = '\x01' - *(char *)((int)psVar5 + 5);
      }
      else {
        FUN_8000bb38(0,0xb3);
      }
    }
    local_20 = (double)(longlong)(int)FLOAT_803dc074;
    *param_1 = *param_1 + (short)(int)FLOAT_803dc074 * 0x82;
  }
  if ((*(char *)((int)psVar5 + 5) != '\0') && (*(char *)(psVar5 + 3) != '\0')) {
    *(undefined *)(psVar5 + 3) = 0;
    FUN_8000bb38((uint)param_1,0x80);
    FUN_8000bb38(0,0x109);
  }
  if (*(char *)((int)psVar5 + 5) != *(char *)((int)psVar5 + 7)) {
    if (*(char *)((int)psVar5 + 5) == '\0') {
      FUN_8000b7dc((int)param_1,0x40);
      (**(code **)(*DAT_803dd6f8 + 0x14))(param_1);
      if (((int)*psVar5 != 0xffffffff) && (uVar3 = FUN_80020078((int)*psVar5), uVar3 != 0)) {
        FUN_800201ac((int)*psVar5,0);
      }
    }
    else {
      if (((int)*psVar5 != 0xffffffff) && (uVar3 = FUN_80020078((int)*psVar5), uVar3 == 0)) {
        FUN_800201ac((int)*psVar5,1);
      }
      *(undefined *)(psVar5 + 3) = 1;
    }
  }
  return;
}

