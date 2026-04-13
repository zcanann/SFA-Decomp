// Function: FUN_80011ed0
// Entry: 80011ed0
// Size: 996 bytes

void FUN_80011ed0(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)

{
  int *piVar1;
  int iVar2;
  uint uVar3;
  uint uVar4;
  short *psVar5;
  int iVar6;
  short *psVar7;
  int iVar8;
  int iVar9;
  short *psVar10;
  int iVar11;
  double extraout_f1;
  double extraout_f1_00;
  double dVar12;
  undefined8 uVar13;
  short local_78;
  undefined2 local_76;
  undefined2 local_74;
  undefined local_6d;
  float local_68;
  float local_64;
  float local_60 [2];
  undefined8 local_58;
  undefined8 local_50;
  undefined8 local_48;
  undefined8 local_40;
  undefined8 local_38;
  undefined8 local_30;
  
  uVar13 = FUN_80286830();
  piVar1 = (int *)((ulonglong)uVar13 >> 0x20);
  iVar6 = (int)uVar13;
  if (iVar6 < 0) {
    iVar6 = 10;
  }
  uVar4 = piVar1[6];
  psVar5 = (short *)(*piVar1 + uVar4 * 0xe);
  *(undefined *)((int)psVar5 + 0xb) = 0xff;
  while (uVar3 = (uint)*(byte *)(psVar5 + 5), uVar3 != 0xff) {
    psVar5 = (short *)(*piVar1 + uVar3 * 0xe);
    *(char *)((int)psVar5 + 0xb) = (char)uVar4;
    uVar4 = uVar3;
  }
  local_78 = *(short *)((int)piVar1 + 0x12);
  local_76 = *(undefined2 *)(piVar1 + 5);
  local_74 = *(undefined2 *)((int)piVar1 + 0x16);
  local_6d = (char)uVar4;
  if (*(byte *)((int)psVar5 + 0xb) == 0xff) {
    psVar7 = (short *)0x0;
  }
  else {
    psVar7 = (short *)(*piVar1 + (uint)*(byte *)((int)psVar5 + 0xb) * 0xe);
  }
  psVar10 = &local_78;
  iVar11 = 0;
  iVar9 = 0;
  dVar12 = extraout_f1;
  while ((iVar9 < iVar6 && (psVar7 != (short *)0x0))) {
    iVar8 = iVar9;
    if (((*psVar10 != *psVar7) || (psVar10[2] != psVar7[2])) &&
       (iVar2 = FUN_80011a1c(dVar12,param_2,param_3,param_4,param_5,param_6,param_7,param_8,psVar7,
                             psVar10,(undefined4 *)0x0), dVar12 = extraout_f1_00, iVar2 == 0)) {
      local_58 = (double)CONCAT44(0x43300000,*psVar5 * 10 + 5U ^ 0x80000000);
      local_68 = (float)(local_58 - DOUBLE_803df328);
      local_50 = (double)CONCAT44(0x43300000,psVar5[1] * 10 + 5U ^ 0x80000000);
      param_2 = (double)(float)(local_50 - DOUBLE_803df328);
      local_64 = (float)(local_50 - DOUBLE_803df328);
      local_48 = (double)CONCAT44(0x43300000,psVar5[2] * 10 + 5U ^ 0x80000000);
      param_3 = (double)(float)(local_48 - DOUBLE_803df328);
      local_60[0] = (float)(local_48 - DOUBLE_803df328);
      if (DAT_803dd54c != 0) {
        FUN_8000e0c0((double)(float)(local_58 - DOUBLE_803df328),param_2,param_3,&local_68,&local_64
                     ,local_60,DAT_803dd54c);
      }
      dVar12 = DOUBLE_803df328;
      local_48 = (double)(longlong)(int)local_68;
      local_50 = (double)CONCAT44(0x43300000,(int)local_68 + 5U ^ 0x80000000);
      *(float *)(piVar1[2] + iVar11) = (float)(local_50 - DOUBLE_803df328);
      local_58 = (double)(longlong)(int)local_64;
      local_40 = (double)CONCAT44(0x43300000,(int)local_64 ^ 0x80000000);
      *(float *)(piVar1[2] + iVar11 + 4) = (float)(local_40 - dVar12);
      iVar11 = iVar11 + 0xc;
      local_38 = (double)(longlong)(int)local_60[0];
      local_30 = (double)CONCAT44(0x43300000,(int)local_60[0] + 5U ^ 0x80000000);
      iVar8 = iVar9 + 1;
      *(float *)(piVar1[2] + iVar9 * 0xc + 8) = (float)(local_30 - dVar12);
      psVar10 = psVar7;
    }
    psVar5 = psVar7;
    iVar9 = iVar8;
    if (*(byte *)((int)psVar7 + 0xb) == 0xff) {
      psVar7 = (short *)0x0;
    }
    else {
      psVar7 = (short *)(*piVar1 + (uint)*(byte *)((int)psVar7 + 0xb) * 0xe);
    }
  }
  if (iVar9 < iVar6) {
    local_30 = (double)CONCAT44(0x43300000,*psVar5 * 10 + 5U ^ 0x80000000);
    local_68 = (float)(local_30 - DOUBLE_803df328);
    local_38 = (double)CONCAT44(0x43300000,psVar5[1] * 10 + 5U ^ 0x80000000);
    local_64 = (float)(local_38 - DOUBLE_803df328);
    local_40 = (double)CONCAT44(0x43300000,psVar5[2] * 10 + 5U ^ 0x80000000);
    local_60[0] = (float)(local_40 - DOUBLE_803df328);
    if (DAT_803dd54c != 0) {
      FUN_8000e0c0((double)local_68,(double)local_64,(double)local_60[0],&local_68,&local_64,
                   local_60,DAT_803dd54c);
    }
    dVar12 = DOUBLE_803df328;
    local_30 = (double)(longlong)(int)local_68;
    local_38 = (double)CONCAT44(0x43300000,(int)local_68 + 5U ^ 0x80000000);
    iVar6 = iVar9 * 0xc;
    *(float *)(piVar1[2] + iVar6) = (float)(local_38 - DOUBLE_803df328);
    local_40 = (double)(longlong)(int)local_64;
    local_48 = (double)CONCAT44(0x43300000,(int)local_64 ^ 0x80000000);
    *(float *)(piVar1[2] + iVar6 + 4) = (float)(local_48 - dVar12);
    local_50 = (double)(longlong)(int)local_60[0];
    local_58 = (double)CONCAT44(0x43300000,(int)local_60[0] + 5U ^ 0x80000000);
    iVar9 = iVar9 + 1;
    *(float *)(piVar1[2] + iVar6 + 8) = (float)(local_58 - dVar12);
    if (9 < iVar9) {
      iVar9 = 10;
    }
  }
  *(short *)(piVar1 + 8) = (short)iVar9;
  *(undefined2 *)((int)piVar1 + 0x22) = 0;
  FUN_8028687c();
  return;
}

