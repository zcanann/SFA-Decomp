// Function: FUN_80108b18
// Entry: 80108b18
// Size: 596 bytes

void FUN_80108b18(void)

{
  bool bVar1;
  short sVar2;
  float fVar3;
  short *psVar4;
  int iVar5;
  undefined4 in_r6;
  undefined4 in_r7;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  int iVar6;
  int iVar7;
  double dVar8;
  double dVar9;
  double dVar10;
  undefined8 in_f4;
  undefined8 in_f5;
  undefined8 in_f6;
  undefined8 in_f7;
  undefined8 in_f8;
  undefined8 uVar11;
  int local_38 [2];
  undefined8 local_30;
  undefined4 local_28;
  uint uStack_24;
  
  uVar11 = FUN_80286840();
  psVar4 = (short *)((ulonglong)uVar11 >> 0x20);
  *(undefined4 *)(psVar4 + 0xc) = *(undefined4 *)(DAT_803de1c0 + 0x120);
  *(undefined4 *)(psVar4 + 0xe) = *(undefined4 *)(DAT_803de1c0 + 0x124);
  *(undefined4 *)(psVar4 + 0x10) = *(undefined4 *)(DAT_803de1c0 + 0x128);
  psVar4[1] = 0;
  bVar1 = *(float *)(psVar4 + 0x7a) <= FLOAT_803e2444;
  iVar6 = (int)(FLOAT_803e2494 * *(float *)(psVar4 + 0x7a));
  local_30 = (double)(longlong)iVar6;
  iVar7 = *(int *)(psVar4 + 0x52);
  if (iVar6 < 1) {
    iVar6 = 1;
  }
  if (iVar7 != 0) {
    *(char *)(iVar7 + 0x36) = (char)iVar6;
    iVar5 = FUN_8002bac4();
    if (((iVar5 == iVar7) && (FUN_80296e34(iVar7,local_38), local_38[0] != 0)) &&
       (*(char *)(local_38[0] + 0x36) = (char)iVar6, *(char *)(local_38[0] + 0x36) == '\x01')) {
      *(undefined *)(local_38[0] + 0x36) = 0;
    }
  }
  if (bVar1) {
    *(int *)(DAT_803de1c0 + 0xfc) = DAT_803de1c0 + 0x40;
    *(undefined4 *)(DAT_803de1c0 + 0x100) = 0;
    *(undefined4 *)(DAT_803de1c0 + 0x104) = 0;
    *(undefined4 *)(DAT_803de1c0 + 0x108) = 4;
    *(code **)(DAT_803de1c0 + 0x10c) = FUN_80010de0;
    *(undefined **)(DAT_803de1c0 + 0x110) = &LAB_80010d74;
    *(undefined4 *)(DAT_803de1c0 + 0xf8) = 0;
    dVar8 = DOUBLE_803e2458;
    local_30 = (double)CONCAT44(0x43300000,(int)*psVar4 ^ 0x80000000);
    *(float *)(DAT_803de1c0 + 0x40) = (float)(local_30 - DOUBLE_803e2458);
    sVar2 = *(short *)uVar11;
    uStack_24 = (int)(short)(-0x8000 - sVar2) ^ 0x80000000;
    local_28 = 0x43300000;
    *(float *)(DAT_803de1c0 + 0x44) = (float)((double)CONCAT44(0x43300000,uStack_24) - dVar8);
    dVar8 = (double)*(float *)(DAT_803de1c0 + 0x40);
    dVar10 = (double)*(float *)(DAT_803de1c0 + 0x44);
    dVar9 = (double)(float)(dVar8 - dVar10);
    if (((double)FLOAT_803e2498 <= dVar9) || (dVar9 <= (double)FLOAT_803e249c)) {
      if (((double)FLOAT_803e2448 < dVar9) || (dVar9 < (double)FLOAT_803e244c)) {
        if ((double)FLOAT_803e2444 <= dVar8) {
          if (dVar10 < (double)FLOAT_803e2444) {
            dVar8 = (double)*(float *)(DAT_803de1c0 + 0x44);
            *(float *)(DAT_803de1c0 + 0x44) = (float)(dVar8 + (double)FLOAT_803e2450);
          }
        }
        else {
          dVar8 = (double)*(float *)(DAT_803de1c0 + 0x40);
          *(float *)(DAT_803de1c0 + 0x40) = (float)(dVar8 + (double)FLOAT_803e2450);
        }
      }
    }
    else {
      *(float *)(DAT_803de1c0 + 0x44) = *(float *)(DAT_803de1c0 + 0x40);
    }
    fVar3 = FLOAT_803e2444;
    *(float *)(DAT_803de1c0 + 0x48) = FLOAT_803e2444;
    *(float *)(DAT_803de1c0 + 0x4c) = fVar3;
    FUN_80010a8c(dVar8,dVar9,dVar10,in_f4,in_f5,in_f6,in_f7,in_f8,(float *)(DAT_803de1c0 + 0x78),
                 (int)sVar2,0x43300000,in_r6,in_r7,in_r8,in_r9,in_r10);
  }
  FUN_8028688c();
  return;
}

