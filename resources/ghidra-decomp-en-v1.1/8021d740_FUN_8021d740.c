// Function: FUN_8021d740
// Entry: 8021d740
// Size: 1216 bytes

void FUN_8021d740(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)

{
  uint uVar1;
  uint uVar2;
  uint *puVar3;
  int *piVar4;
  undefined4 in_r6;
  undefined4 uVar5;
  int iVar6;
  undefined4 in_r7;
  undefined4 uVar7;
  undefined4 in_r8;
  undefined4 uVar8;
  undefined4 in_r9;
  undefined4 in_r10;
  uint uVar9;
  short *psVar10;
  int iVar11;
  int iVar12;
  double dVar13;
  undefined8 uVar14;
  short local_28 [20];
  
  uVar14 = FUN_80286838();
  iVar6 = (int)((ulonglong)uVar14 >> 0x20);
  puVar3 = (uint *)uVar14;
  iVar12 = *(int *)(iVar6 + 0xb8);
  iVar11 = *(int *)(iVar6 + 0x4c);
  if ((*(char *)((int)puVar3 + 0x27a) != '\0') || ((*(byte *)(iVar12 + 0xc49) >> 1 & 1) != 0)) {
    if (*(char *)(iVar12 + 0xc4a) < '\0') {
      *(undefined *)(iVar12 + 0xc4b) = 9;
    }
    else {
      *(undefined *)(iVar12 + 0xc4b) = 0;
    }
    *(byte *)(iVar12 + 0x9fd) = *(byte *)(iVar12 + 0x9fd) & 0xfe;
    *(byte *)(iVar12 + 0xc49) = *(byte *)(iVar12 + 0xc49) & 0xbf;
    *(undefined *)(iVar12 + 0xc42) = 0;
    *(byte *)(iVar12 + 0xc49) = *(byte *)(iVar12 + 0xc49) & 0xfd;
    *puVar3 = *puVar3 | 0x1000000;
    FUN_800803f8((undefined4 *)(iVar12 + 0xc2c));
    FUN_80036018(iVar6);
    if (*(short *)(iVar6 + 0xa0) != 2) {
      FUN_8002f66c(iVar6,0x78);
      FUN_8003042c((double)FLOAT_803e7740,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                   iVar6,2,0,in_r6,in_r7,in_r8,in_r9,in_r10);
      puVar3[0xa8] = (uint)FLOAT_803e7744;
    }
    puVar3[0xa8] = (uint)FLOAT_803e7744;
    uVar2 = FUN_80020078(0x3f0);
    *(undefined4 *)(iVar12 + 0xc3c) = 9;
    uVar9 = 0;
    psVar10 = (short *)&DAT_803dcf98;
    do {
      uVar1 = uVar9 ^ uVar2 - 1;
      FUN_800201ac((int)*psVar10,((int)uVar1 >> 1) - (uVar1 & uVar9) >> 0x1f);
      psVar10 = psVar10 + 1;
      uVar9 = uVar9 + 1;
    } while ((int)uVar9 < 4);
    if (uVar2 - 1 == 3) {
      FUN_800201ac(0x3f4,1);
      goto LAB_8021dbe8;
    }
  }
  uVar2 = FUN_80020078((int)*(short *)(iVar11 + 0x1e));
  if (uVar2 == 0) {
    *(byte *)(iVar6 + 0xaf) = *(byte *)(iVar6 + 0xaf) | 8;
    uVar2 = FUN_8008038c(100);
    if (uVar2 != 0) {
      uVar2 = FUN_80022264(0,0);
      in_r6 = 1;
      FUN_800393e8(iVar6,iVar12 + 0x3bc,(ushort *)(&DAT_803dcf70 + uVar2 * 6),1);
    }
    if (*(char *)((int)puVar3 + 0x346) != '\0') {
      uVar2 = FUN_8008038c(2);
      if (uVar2 == 0) {
        FUN_8002f66c(iVar6,0x78);
        FUN_8003042c((double)FLOAT_803e7740,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                     iVar6,2,0,in_r6,in_r7,in_r8,in_r9,in_r10);
        puVar3[0xa8] = (uint)FLOAT_803e7744;
      }
      else {
        FUN_8002f66c(iVar6,0x78);
        FUN_8003042c((double)FLOAT_803e7740,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                     iVar6,9,0,in_r6,in_r7,in_r8,in_r9,in_r10);
        puVar3[0xa8] = (uint)FLOAT_803e7748;
      }
    }
  }
  else {
    FUN_8011f68c(local_28);
    uVar2 = FUN_80020078(0xaf7);
    if (((uVar2 == 0) || (iVar11 = FUN_8012f000(), iVar11 == -1)) && (local_28[0] != 0xaf7)) {
      uVar5 = 0;
      uVar7 = 0;
      uVar8 = 2;
      FUN_8002b7b0(iVar6,0,0,0,'\0','\x02');
    }
    else {
      uVar5 = 0;
      uVar7 = 0;
      uVar8 = 4;
      FUN_8002b7b0(iVar6,0,0,0,'\0','\x04');
    }
    iVar11 = FUN_8003809c(iVar6,0xaf7);
    if (iVar11 == 0) {
      if ((*(char *)((int)puVar3 + 0x346) != '\0') && (*(short *)(iVar6 + 0xa0) != 2)) {
        FUN_8002f66c(iVar6,0x78);
        FUN_8003042c((double)FLOAT_803e7740,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                     iVar6,2,0,uVar5,uVar7,uVar8,in_r9,in_r10);
        puVar3[0xa8] = (uint)FLOAT_803e7744;
      }
      uVar2 = FUN_800803dc((float *)(iVar12 + 0xc2c));
      if (uVar2 == 0) {
        iVar11 = FUN_8002bac4();
        dVar13 = (double)FUN_800217c8((float *)(iVar11 + 0x18),(float *)(iVar6 + 0x18));
        if (((double)FLOAT_803e773c < dVar13) && (uVar2 = FUN_8008038c(500), uVar2 != 0)) {
          uVar2 = FUN_80022264(0,100);
          iVar6 = 0;
          for (piVar4 = &DAT_8032b794; *piVar4 < (int)uVar2; piVar4 = piVar4 + 1) {
            uVar2 = uVar2 - (&DAT_8032b794)[iVar6];
            iVar6 = iVar6 + 1;
          }
          *(char *)(iVar12 + 0xc42) = (char)iVar6;
          *(byte *)(iVar12 + 0x9fd) = *(byte *)(iVar12 + 0x9fd) | 1;
          FUN_80080404((float *)(iVar12 + 0xc2c),0x14);
        }
      }
      else {
        iVar11 = FUN_80080434((float *)(iVar12 + 0xc2c));
        if (iVar11 != 0) {
          *(undefined *)(iVar12 + 0xc4b) = 0xff;
          (**(code **)(*DAT_803dd6d4 + 0x48))
                    ((&DAT_8032b788)[*(byte *)(iVar12 + 0xc42)],iVar6,0xffffffff);
        }
      }
    }
    else {
      uVar2 = FUN_80020078(0x3f0);
      uVar9 = FUN_80020078(0xaf7);
      FUN_800201ac(0x3f0,uVar2 + uVar9);
      FUN_800201ac(0xaf7,0);
      uVar2 = FUN_8008038c(5 - (uVar2 + uVar9));
      if (uVar2 == 0) {
        *(undefined *)(iVar12 + 0xc4b) = 9;
      }
      else {
        *(undefined *)(iVar12 + 0xc4b) = 2;
      }
      FUN_8003ab38(iVar6);
      FUN_8002f66c(iVar6,0);
      FUN_8003042c((double)FLOAT_803e7740,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                   iVar6,0,0,uVar5,uVar7,uVar8,in_r9,in_r10);
      FUN_80035ff8(iVar6);
      FUN_8002b7b0(iVar6,0,0,0,'\0','\x02');
      (**(code **)(*DAT_803dd6d4 + 0x48))(1,iVar6,0xffffffff);
    }
  }
LAB_8021dbe8:
  FUN_80286884();
  return;
}

