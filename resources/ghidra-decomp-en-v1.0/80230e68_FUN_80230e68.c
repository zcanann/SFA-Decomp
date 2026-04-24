// Function: FUN_80230e68
// Entry: 80230e68
// Size: 424 bytes

void FUN_80230e68(int param_1)

{
  int iVar1;
  int iVar2;
  float fVar3;
  uint uVar4;
  undefined4 uVar5;
  float *pfVar6;
  double dVar7;
  float local_48;
  float local_44;
  float local_40;
  longlong local_38;
  longlong local_30;
  undefined4 local_28;
  uint uStack36;
  longlong local_20;
  longlong local_18;
  double local_10;
  
  pfVar6 = *(float **)(param_1 + 0xb8);
  if (*(char *)(pfVar6 + 6) == '\0') {
    iVar1 = (int)-pfVar6[3];
    local_38 = (longlong)iVar1;
    iVar2 = (int)pfVar6[3];
    local_30 = (longlong)iVar2;
    uStack36 = FUN_800221a0(iVar1,iVar2);
    uStack36 = uStack36 ^ 0x80000000;
    local_28 = 0x43300000;
    local_48 = (float)((double)CONCAT44(0x43300000,uStack36) - DOUBLE_803e70f8);
    iVar1 = (int)-pfVar6[4];
    local_20 = (longlong)iVar1;
    iVar2 = (int)pfVar6[4];
    local_18 = (longlong)iVar2;
    uVar4 = FUN_800221a0(iVar1,iVar2);
    local_10 = (double)CONCAT44(0x43300000,uVar4 ^ 0x80000000);
    local_44 = (float)(local_10 - DOUBLE_803e70f8);
    local_40 = pfVar6[5];
    uVar5 = FUN_8000f558();
    FUN_80247494(uVar5,&local_48,param_1 + 0xc);
    *(float *)(param_1 + 0xc) = *(float *)(param_1 + 0xc) + FLOAT_803dcdd8;
    *(float *)(param_1 + 0x14) = *(float *)(param_1 + 0x14) + FLOAT_803dcddc;
    *(byte *)(pfVar6 + 6) = *(byte *)(pfVar6 + 6) | 1;
    pfVar6[2] = FLOAT_803e7104;
  }
  fVar3 = FLOAT_803e7104;
  dVar7 = (double)FLOAT_803e7104;
  if (dVar7 < (double)pfVar6[1]) {
    pfVar6[1] = (float)((double)pfVar6[1] - (double)FLOAT_803db414);
    if (dVar7 < (double)pfVar6[1]) {
      FUN_8002b95c(dVar7,dVar7,(double)(*pfVar6 * FLOAT_803db414),param_1);
      pfVar6[2] = FLOAT_803e7108 * FLOAT_803db414 + pfVar6[2];
      if (FLOAT_803e710c < pfVar6[2]) {
        pfVar6[2] = FLOAT_803e710c;
      }
      *(char *)(param_1 + 0x36) = (char)(int)pfVar6[2];
    }
    else {
      pfVar6[1] = fVar3;
      FUN_8002cbc4(param_1);
    }
  }
  return;
}

