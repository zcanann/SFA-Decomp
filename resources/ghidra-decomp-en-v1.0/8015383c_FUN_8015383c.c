// Function: FUN_8015383c
// Entry: 8015383c
// Size: 960 bytes

void FUN_8015383c(short *param_1,int param_2)

{
  bool bVar1;
  int iVar2;
  char cVar5;
  short sVar3;
  undefined uVar6;
  ushort uVar4;
  double dVar7;
  undefined auStack72 [4];
  undefined auStack68 [8];
  undefined auStack60 [8];
  float local_34;
  float local_30;
  float local_2c;
  undefined4 local_28;
  float local_24;
  undefined4 local_20;
  undefined4 local_18;
  uint uStack20;
  
  *(byte *)(param_2 + 0x33b) = *(byte *)(param_2 + 0x33b) & 0x7f;
  bVar1 = false;
  iVar2 = *(int *)(param_2 + 0x29c);
  local_34 = *(float *)(param_1 + 6) - *(float *)(iVar2 + 0xc);
  local_30 = *(float *)(param_1 + 8) - *(float *)(iVar2 + 0x10);
  local_2c = *(float *)(param_1 + 10) - *(float *)(iVar2 + 0x14);
  dVar7 = (double)FUN_802477f0(&local_34);
  if (((double)FLOAT_803e2900 <= dVar7) ||
     ((*(ushort *)(*(int *)(param_2 + 0x29c) + 0xb0) & 0x1000) != 0)) {
    cVar5 = '\0';
  }
  else {
    local_28 = *(undefined4 *)(param_1 + 6);
    local_24 = FLOAT_803e2904 + *(float *)(param_1 + 8);
    local_20 = *(undefined4 *)(param_1 + 10);
    FUN_80012d00(&local_28,auStack68);
    iVar2 = *(int *)(param_2 + 0x29c);
    local_28 = *(undefined4 *)(iVar2 + 0xc);
    local_24 = FLOAT_803e2908 + *(float *)(iVar2 + 0x10);
    local_20 = *(undefined4 *)(iVar2 + 0x14);
    FUN_80012d00(&local_28,auStack60);
    cVar5 = FUN_800128dc(auStack60,auStack68,0,auStack72,0);
    if (cVar5 != '\0') {
      FUN_8014cf7c((double)*(float *)(*(int *)(param_2 + 0x29c) + 0xc),
                   (double)*(float *)(*(int *)(param_2 + 0x29c) + 0x14),param_1,param_2,0x14,0);
      sVar3 = FUN_800217c0((double)local_34,(double)local_2c);
      sVar3 = sVar3 - *param_1;
      if (0x8000 < sVar3) {
        sVar3 = sVar3 + 1;
      }
      if (sVar3 < -0x8000) {
        sVar3 = sVar3 + -1;
      }
      if (sVar3 < 0) {
        sVar3 = -sVar3;
      }
      if (sVar3 < 1000) {
        bVar1 = true;
      }
    }
  }
  if ((*(byte *)(param_2 + 0x33b) & 0x40) == 0) {
    FUN_8000b4d0(param_1,0x49b,2);
    FUN_8014d08c((double)FLOAT_803e290c,param_1,param_2,2,0,0);
    *(byte *)(param_2 + 0x33b) = *(byte *)(param_2 + 0x33b) | 0x40;
    *(undefined *)(param_2 + 0x33a) = 0;
  }
  else if ((*(uint *)(param_2 + 0x2dc) & 0x40000000) != 0) {
    if (cVar5 == '\0') {
      uVar4 = FUN_800221a0(2,4);
      uVar4 = uVar4 & 0xff;
      if (uVar4 == 2) {
        uVar4 = 0;
      }
      else if (uVar4 == 4) {
        FUN_8000bb18(param_1,0x357);
      }
    }
    else if (*(char *)(param_2 + 0x33a) == '\0') {
      if ((param_1[0x50] == 5) || (!bVar1)) {
        uVar4 = 4;
        uVar6 = FUN_800221a0(1,2);
        *(undefined *)(param_2 + 0x33a) = uVar6;
      }
      else {
        uVar4 = 5;
        *(undefined *)(param_2 + 0x33a) = (&DAT_803dbcc0)[*(byte *)(param_2 + 0x33b) & 3];
        *(byte *)(param_2 + 0x33b) = *(char *)(param_2 + 0x33b) + 1U & 0xc3;
      }
    }
    else {
      *(char *)(param_2 + 0x33a) = *(char *)(param_2 + 0x33a) + -1;
      uVar4 = param_1[0x50] & 0xff;
    }
    FUN_8014d08c((double)FLOAT_803e2910,param_1,param_2,uVar4,0,0);
  }
  if (param_1[0x50] == 5) {
    if ((DOUBLE_803e2918 <= (double)*(float *)(param_1 + 0x4c)) &&
       ((double)*(float *)(param_1 + 0x4c) <
        DOUBLE_803e2918 + (double)(*(float *)(param_2 + 0x308) * FLOAT_803db414))) {
      FUN_80153640(param_1,param_2);
      goto LAB_80153bd0;
    }
  }
  *(float *)(param_2 + 0x324) = *(float *)(param_2 + 0x324) - FLOAT_803db414;
  if (*(float *)(param_2 + 0x324) <= FLOAT_803e2920) {
    uStack20 = FUN_800221a0(0x96,300);
    uStack20 = uStack20 ^ 0x80000000;
    local_18 = 0x43300000;
    *(float *)(param_2 + 0x324) = (float)((double)CONCAT44(0x43300000,uStack20) - DOUBLE_803e28f8);
    FUN_8000bb18(param_1,0x245);
  }
LAB_80153bd0:
  FUN_8015355c(param_1,param_2);
  return;
}

