// Function: FUN_8010887c
// Entry: 8010887c
// Size: 596 bytes

void FUN_8010887c(void)

{
  bool bVar1;
  float fVar2;
  float fVar3;
  double dVar4;
  short *psVar5;
  int iVar6;
  undefined4 uVar7;
  int iVar8;
  int iVar9;
  undefined8 uVar10;
  int local_38 [2];
  double local_30;
  undefined4 local_28;
  uint uStack36;
  
  uVar10 = FUN_802860dc();
  psVar5 = (short *)((ulonglong)uVar10 >> 0x20);
  *(undefined4 *)(psVar5 + 0xc) = *(undefined4 *)(DAT_803dd548 + 0x120);
  *(undefined4 *)(psVar5 + 0xe) = *(undefined4 *)(DAT_803dd548 + 0x124);
  *(undefined4 *)(psVar5 + 0x10) = *(undefined4 *)(DAT_803dd548 + 0x128);
  psVar5[1] = 0;
  bVar1 = FLOAT_803e17c4 < *(float *)(psVar5 + 0x7a);
  iVar8 = (int)(FLOAT_803e1814 * *(float *)(psVar5 + 0x7a));
  local_30 = (double)(longlong)iVar8;
  iVar9 = *(int *)(psVar5 + 0x52);
  if (iVar8 < 1) {
    iVar8 = 1;
  }
  if (iVar9 != 0) {
    *(char *)(iVar9 + 0x36) = (char)iVar8;
    iVar6 = FUN_8002b9ec();
    if (((iVar6 == iVar9) && (FUN_802966d4(iVar9,local_38), local_38[0] != 0)) &&
       (*(char *)(local_38[0] + 0x36) = (char)iVar8, *(char *)(local_38[0] + 0x36) == '\x01')) {
      *(undefined *)(local_38[0] + 0x36) = 0;
    }
  }
  if (bVar1) {
    uVar7 = 0;
  }
  else {
    *(int *)(DAT_803dd548 + 0xfc) = DAT_803dd548 + 0x40;
    *(undefined4 *)(DAT_803dd548 + 0x100) = 0;
    *(undefined4 *)(DAT_803dd548 + 0x104) = 0;
    *(undefined4 *)(DAT_803dd548 + 0x108) = 4;
    *(code **)(DAT_803dd548 + 0x10c) = FUN_80010dc0;
    *(undefined **)(DAT_803dd548 + 0x110) = &LAB_80010d54;
    *(undefined4 *)(DAT_803dd548 + 0xf8) = 0;
    dVar4 = DOUBLE_803e17d8;
    local_30 = (double)CONCAT44(0x43300000,(int)*psVar5 ^ 0x80000000);
    *(float *)(DAT_803dd548 + 0x40) = (float)(local_30 - DOUBLE_803e17d8);
    uStack36 = (int)(short)(-0x8000 - *(short *)uVar10) ^ 0x80000000;
    local_28 = 0x43300000;
    *(float *)(DAT_803dd548 + 0x44) = (float)((double)CONCAT44(0x43300000,uStack36) - dVar4);
    fVar2 = *(float *)(DAT_803dd548 + 0x40);
    fVar3 = fVar2 - *(float *)(DAT_803dd548 + 0x44);
    if ((FLOAT_803e1818 <= fVar3) || (fVar3 <= FLOAT_803e181c)) {
      if ((FLOAT_803e17c8 < fVar3) || (fVar3 < FLOAT_803e17cc)) {
        if (FLOAT_803e17c4 <= fVar2) {
          if (*(float *)(DAT_803dd548 + 0x44) < FLOAT_803e17c4) {
            *(float *)(DAT_803dd548 + 0x44) = *(float *)(DAT_803dd548 + 0x44) + FLOAT_803e17d0;
          }
        }
        else {
          *(float *)(DAT_803dd548 + 0x40) = *(float *)(DAT_803dd548 + 0x40) + FLOAT_803e17d0;
        }
      }
    }
    else {
      *(float *)(DAT_803dd548 + 0x44) = fVar2;
    }
    fVar2 = FLOAT_803e17c4;
    *(float *)(DAT_803dd548 + 0x48) = FLOAT_803e17c4;
    *(float *)(DAT_803dd548 + 0x4c) = fVar2;
    FUN_80010a6c(DAT_803dd548 + 0x78);
    uVar7 = 1;
  }
  FUN_80286128(uVar7);
  return;
}

