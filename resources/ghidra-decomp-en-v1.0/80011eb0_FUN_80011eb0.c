// Function: FUN_80011eb0
// Entry: 80011eb0
// Size: 996 bytes

void FUN_80011eb0(void)

{
  double dVar1;
  int *piVar2;
  int iVar3;
  uint uVar4;
  uint uVar5;
  short *psVar6;
  int iVar7;
  short *psVar8;
  int iVar9;
  int iVar10;
  short *psVar11;
  int iVar12;
  undefined8 uVar13;
  short local_78;
  undefined2 local_76;
  undefined2 local_74;
  undefined local_6d;
  float local_68;
  float local_64;
  float local_60 [2];
  double local_58;
  double local_50;
  double local_48;
  double local_40;
  double local_38;
  double local_30;
  
  uVar13 = FUN_802860cc();
  piVar2 = (int *)((ulonglong)uVar13 >> 0x20);
  iVar7 = (int)uVar13;
  if (iVar7 < 0) {
    iVar7 = 10;
  }
  uVar5 = piVar2[6];
  psVar6 = (short *)(*piVar2 + uVar5 * 0xe);
  *(undefined *)((int)psVar6 + 0xb) = 0xff;
  while (uVar4 = (uint)*(byte *)(psVar6 + 5), uVar4 != 0xff) {
    psVar6 = (short *)(*piVar2 + uVar4 * 0xe);
    *(char *)((int)psVar6 + 0xb) = (char)uVar5;
    uVar5 = uVar4;
  }
  local_78 = *(short *)((int)piVar2 + 0x12);
  local_76 = *(undefined2 *)(piVar2 + 5);
  local_74 = *(undefined2 *)((int)piVar2 + 0x16);
  local_6d = (char)uVar5;
  if (*(byte *)((int)psVar6 + 0xb) == 0xff) {
    psVar8 = (short *)0x0;
  }
  else {
    psVar8 = (short *)(*piVar2 + (uint)*(byte *)((int)psVar6 + 0xb) * 0xe);
  }
  psVar11 = &local_78;
  iVar12 = 0;
  iVar10 = 0;
  while ((iVar10 < iVar7 && (psVar8 != (short *)0x0))) {
    iVar9 = iVar10;
    if (((*psVar11 != *psVar8) || (psVar11[2] != psVar8[2])) &&
       (iVar3 = FUN_800119fc(psVar8,psVar11,0), iVar3 == 0)) {
      local_58 = (double)CONCAT44(0x43300000,*psVar6 * 10 + 5U ^ 0x80000000);
      local_68 = (float)(local_58 - DOUBLE_803de6a8);
      local_50 = (double)CONCAT44(0x43300000,psVar6[1] * 10 + 5U ^ 0x80000000);
      local_64 = (float)(local_50 - DOUBLE_803de6a8);
      local_48 = (double)CONCAT44(0x43300000,psVar6[2] * 10 + 5U ^ 0x80000000);
      local_60[0] = (float)(local_48 - DOUBLE_803de6a8);
      if (DAT_803dc8cc != 0) {
        FUN_8000e0a0(&local_68,&local_64,local_60);
      }
      dVar1 = DOUBLE_803de6a8;
      local_48 = (double)(longlong)(int)local_68;
      local_50 = (double)CONCAT44(0x43300000,(int)local_68 + 5U ^ 0x80000000);
      *(float *)(piVar2[2] + iVar12) = (float)(local_50 - DOUBLE_803de6a8);
      local_58 = (double)(longlong)(int)local_64;
      local_40 = (double)CONCAT44(0x43300000,(int)local_64 ^ 0x80000000);
      *(float *)(piVar2[2] + iVar12 + 4) = (float)(local_40 - dVar1);
      iVar12 = iVar12 + 0xc;
      local_38 = (double)(longlong)(int)local_60[0];
      local_30 = (double)CONCAT44(0x43300000,(int)local_60[0] + 5U ^ 0x80000000);
      iVar9 = iVar10 + 1;
      *(float *)(piVar2[2] + iVar10 * 0xc + 8) = (float)(local_30 - dVar1);
      psVar11 = psVar8;
    }
    psVar6 = psVar8;
    iVar10 = iVar9;
    if (*(byte *)((int)psVar8 + 0xb) == 0xff) {
      psVar8 = (short *)0x0;
    }
    else {
      psVar8 = (short *)(*piVar2 + (uint)*(byte *)((int)psVar8 + 0xb) * 0xe);
    }
  }
  if (iVar10 < iVar7) {
    local_30 = (double)CONCAT44(0x43300000,*psVar6 * 10 + 5U ^ 0x80000000);
    local_68 = (float)(local_30 - DOUBLE_803de6a8);
    local_38 = (double)CONCAT44(0x43300000,psVar6[1] * 10 + 5U ^ 0x80000000);
    local_64 = (float)(local_38 - DOUBLE_803de6a8);
    local_40 = (double)CONCAT44(0x43300000,psVar6[2] * 10 + 5U ^ 0x80000000);
    local_60[0] = (float)(local_40 - DOUBLE_803de6a8);
    if (DAT_803dc8cc != 0) {
      FUN_8000e0a0(&local_68,&local_64,local_60);
    }
    dVar1 = DOUBLE_803de6a8;
    local_30 = (double)(longlong)(int)local_68;
    local_38 = (double)CONCAT44(0x43300000,(int)local_68 + 5U ^ 0x80000000);
    iVar7 = iVar10 * 0xc;
    *(float *)(piVar2[2] + iVar7) = (float)(local_38 - DOUBLE_803de6a8);
    local_40 = (double)(longlong)(int)local_64;
    local_48 = (double)CONCAT44(0x43300000,(int)local_64 ^ 0x80000000);
    *(float *)(piVar2[2] + iVar7 + 4) = (float)(local_48 - dVar1);
    local_50 = (double)(longlong)(int)local_60[0];
    local_58 = (double)CONCAT44(0x43300000,(int)local_60[0] + 5U ^ 0x80000000);
    iVar10 = iVar10 + 1;
    *(float *)(piVar2[2] + iVar7 + 8) = (float)(local_58 - dVar1);
    if (9 < iVar10) {
      iVar10 = 10;
    }
  }
  *(short *)(piVar2 + 8) = (short)iVar10;
  *(undefined2 *)((int)piVar2 + 0x22) = 0;
  FUN_80286118(iVar10);
  return;
}

