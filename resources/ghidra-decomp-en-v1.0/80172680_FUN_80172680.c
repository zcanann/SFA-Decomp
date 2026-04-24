// Function: FUN_80172680
// Entry: 80172680
// Size: 420 bytes

/* WARNING: Removing unreachable block (ram,0x80172804) */

void FUN_80172680(undefined4 param_1,undefined4 param_2,int param_3)

{
  char cVar1;
  float fVar2;
  uint uVar3;
  int iVar4;
  undefined4 uVar5;
  int iVar6;
  int iVar7;
  int iVar8;
  undefined4 uVar9;
  double dVar10;
  double dVar11;
  undefined8 in_f31;
  double dVar12;
  undefined auStack72 [12];
  float local_3c;
  float local_38;
  float local_34;
  undefined auStack8 [8];
  
  uVar9 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  iVar4 = FUN_802860dc();
  iVar8 = *(int *)(iVar4 + 0xb8);
  if (*(short *)(iVar8 + 0x14) != -1) {
    uVar5 = FUN_8001ffb4();
    uVar3 = countLeadingZeros(uVar5);
    *(char *)(iVar8 + 0x1e) = (char)(uVar3 >> 5);
  }
  if ((*(char *)(iVar8 + 0x1e) == '\0') && (*(short *)(iVar4 + 0x46) == 0x6a6)) {
    FUN_800972dc((double)FLOAT_803e3454,(double)FLOAT_803e3458,iVar4,5,6,1,0x14,0,0);
  }
  *(undefined *)(param_3 + 0x56) = 0;
  for (iVar6 = 0; iVar6 < (int)(uint)*(byte *)(param_3 + 0x8b); iVar6 = iVar6 + 1) {
    cVar1 = *(char *)(param_3 + iVar6 + 0x81);
    if (cVar1 == '\x01') {
      dVar10 = (double)FUN_80294204((double)FLOAT_803e3488);
      dVar12 = (double)(float)((double)FLOAT_803e3484 * dVar10);
      dVar11 = (double)FUN_80293e80((double)FLOAT_803e3488);
      dVar10 = (double)FLOAT_803e3484;
      *(undefined *)(*(int *)(iVar4 + 0xb8) + 0x1d) = 8;
      *(float *)(iVar4 + 0x24) = (float)(dVar10 * dVar11);
      fVar2 = FLOAT_803e3460;
      *(float *)(iVar4 + 0x28) = FLOAT_803e3460;
      *(float *)(iVar4 + 0x2c) = (float)dVar12;
      *(undefined *)(*(int *)(iVar4 + 0xb8) + 0x1d) = 8;
      *(float *)(iVar4 + 0x24) = FLOAT_803e348c;
      *(float *)(iVar4 + 0x28) = fVar2;
      *(float *)(iVar4 + 0x2c) = FLOAT_803e345c;
    }
    else if (cVar1 == '\x02') {
      *(undefined *)(iVar8 + 0x3e) = 1;
    }
    else if (cVar1 == '\x03') {
      iVar7 = 0;
      dVar10 = (double)FLOAT_803e345c;
      do {
        local_3c = (float)dVar10;
        local_38 = (float)dVar10;
        local_34 = (float)dVar10;
        (**(code **)(*DAT_803dca88 + 8))(iVar4,0x7ef,auStack72,1,0xffffffff,0);
        iVar7 = iVar7 + 1;
      } while (iVar7 < 10);
    }
  }
  __psq_l0(auStack8,uVar9);
  __psq_l1(auStack8,uVar9);
  FUN_80286128(0);
  return;
}

