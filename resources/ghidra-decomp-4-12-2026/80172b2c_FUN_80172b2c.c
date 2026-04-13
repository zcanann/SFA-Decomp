// Function: FUN_80172b2c
// Entry: 80172b2c
// Size: 420 bytes

/* WARNING: Removing unreachable block (ram,0x80172cb0) */
/* WARNING: Removing unreachable block (ram,0x80172b3c) */

void FUN_80172b2c(undefined4 param_1,undefined4 param_2,int param_3)

{
  char cVar1;
  float fVar2;
  int iVar3;
  uint uVar4;
  int iVar5;
  int iVar6;
  int iVar7;
  double dVar8;
  double dVar9;
  double in_f31;
  double dVar10;
  double in_ps31_1;
  undefined auStack_48 [12];
  float local_3c;
  float local_38;
  float local_34;
  float local_8;
  float fStack_4;
  
  local_8 = (float)in_f31;
  fStack_4 = (float)in_ps31_1;
  iVar3 = FUN_80286840();
  iVar7 = *(int *)(iVar3 + 0xb8);
  if ((int)*(short *)(iVar7 + 0x14) != 0xffffffff) {
    uVar4 = FUN_80020078((int)*(short *)(iVar7 + 0x14));
    uVar4 = countLeadingZeros(uVar4);
    *(char *)(iVar7 + 0x1e) = (char)(uVar4 >> 5);
  }
  if ((*(char *)(iVar7 + 0x1e) == '\0') && (*(short *)(iVar3 + 0x46) == 0x6a6)) {
    FUN_80097568((double)FLOAT_803e40ec,(double)FLOAT_803e40f0,iVar3,5,6,1,0x14,0,0);
  }
  *(undefined *)(param_3 + 0x56) = 0;
  for (iVar5 = 0; iVar5 < (int)(uint)*(byte *)(param_3 + 0x8b); iVar5 = iVar5 + 1) {
    cVar1 = *(char *)(param_3 + iVar5 + 0x81);
    if (cVar1 == '\x01') {
      dVar8 = (double)FUN_80294964();
      dVar10 = (double)(float)((double)FLOAT_803e411c * dVar8);
      dVar9 = (double)FUN_802945e0();
      dVar8 = (double)FLOAT_803e411c;
      *(undefined *)(*(int *)(iVar3 + 0xb8) + 0x1d) = 8;
      *(float *)(iVar3 + 0x24) = (float)(dVar8 * dVar9);
      fVar2 = FLOAT_803e40f8;
      *(float *)(iVar3 + 0x28) = FLOAT_803e40f8;
      *(float *)(iVar3 + 0x2c) = (float)dVar10;
      *(undefined *)(*(int *)(iVar3 + 0xb8) + 0x1d) = 8;
      *(float *)(iVar3 + 0x24) = FLOAT_803e4124;
      *(float *)(iVar3 + 0x28) = fVar2;
      *(float *)(iVar3 + 0x2c) = FLOAT_803e40f4;
    }
    else if (cVar1 == '\x02') {
      *(undefined *)(iVar7 + 0x3e) = 1;
    }
    else if (cVar1 == '\x03') {
      iVar6 = 0;
      dVar8 = (double)FLOAT_803e40f4;
      do {
        local_3c = (float)dVar8;
        local_38 = (float)dVar8;
        local_34 = (float)dVar8;
        (**(code **)(*DAT_803dd708 + 8))(iVar3,0x7ef,auStack_48,1,0xffffffff,0);
        iVar6 = iVar6 + 1;
      } while (iVar6 < 10);
    }
  }
  FUN_8028688c();
  return;
}

