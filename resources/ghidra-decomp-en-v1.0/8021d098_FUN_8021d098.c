// Function: FUN_8021d098
// Entry: 8021d098
// Size: 1216 bytes

void FUN_8021d098(void)

{
  uint uVar1;
  int iVar2;
  undefined4 uVar3;
  int iVar4;
  uint *puVar5;
  int *piVar6;
  uint uVar7;
  short *psVar8;
  int iVar9;
  int iVar10;
  double dVar11;
  undefined8 uVar12;
  short local_28 [20];
  
  uVar12 = FUN_802860d4();
  iVar4 = (int)((ulonglong)uVar12 >> 0x20);
  puVar5 = (uint *)uVar12;
  iVar10 = *(int *)(iVar4 + 0xb8);
  iVar9 = *(int *)(iVar4 + 0x4c);
  if ((*(char *)((int)puVar5 + 0x27a) != '\0') || ((*(byte *)(iVar10 + 0xc49) >> 1 & 1) != 0)) {
    if (*(char *)(iVar10 + 0xc4a) < '\0') {
      *(undefined *)(iVar10 + 0xc4b) = 9;
    }
    else {
      *(undefined *)(iVar10 + 0xc4b) = 0;
    }
    *(byte *)(iVar10 + 0x9fd) = *(byte *)(iVar10 + 0x9fd) & 0xfe;
    *(byte *)(iVar10 + 0xc49) = *(byte *)(iVar10 + 0xc49) & 0xbf;
    *(undefined *)(iVar10 + 0xc42) = 0;
    *(byte *)(iVar10 + 0xc49) = *(byte *)(iVar10 + 0xc49) & 0xfd;
    *puVar5 = *puVar5 | 0x1000000;
    FUN_8008016c(iVar10 + 0xc2c);
    FUN_80035f20(iVar4);
    if (*(short *)(iVar4 + 0xa0) != 2) {
      FUN_8002f574(iVar4,0x78);
      FUN_80030334((double)FLOAT_803e6aa8,iVar4,2,0);
      puVar5[0xa8] = (uint)FLOAT_803e6aac;
    }
    puVar5[0xa8] = (uint)FLOAT_803e6aac;
    iVar2 = FUN_8001ffb4(0x3f0);
    *(undefined4 *)(iVar10 + 0xc3c) = 9;
    uVar7 = 0;
    psVar8 = (short *)&DAT_803dc330;
    do {
      uVar1 = uVar7 ^ iVar2 - 1U;
      FUN_800200e8((int)*psVar8,((int)uVar1 >> 1) - (uVar1 & uVar7) >> 0x1f);
      psVar8 = psVar8 + 1;
      uVar7 = uVar7 + 1;
    } while ((int)uVar7 < 4);
    if (iVar2 - 1U == 3) {
      FUN_800200e8(0x3f4,1);
      uVar3 = 0xb;
      goto LAB_8021d540;
    }
  }
  iVar9 = FUN_8001ffb4((int)*(short *)(iVar9 + 0x1e));
  if (iVar9 == 0) {
    *(byte *)(iVar4 + 0xaf) = *(byte *)(iVar4 + 0xaf) | 8;
    iVar9 = FUN_80080100(100);
    if (iVar9 != 0) {
      iVar9 = FUN_800221a0(0,0);
      FUN_800392f0(iVar4,iVar10 + 0x3bc,&DAT_803dc308 + iVar9 * 6,1);
    }
    if (*(char *)((int)puVar5 + 0x346) != '\0') {
      iVar9 = FUN_80080100(2);
      if (iVar9 == 0) {
        FUN_8002f574(iVar4,0x78);
        FUN_80030334((double)FLOAT_803e6aa8,iVar4,2,0);
        puVar5[0xa8] = (uint)FLOAT_803e6aac;
      }
      else {
        FUN_8002f574(iVar4,0x78);
        FUN_80030334((double)FLOAT_803e6aa8,iVar4,9,0);
        puVar5[0xa8] = (uint)FLOAT_803e6ab0;
      }
    }
    uVar3 = 0;
  }
  else {
    FUN_8011f3a8(local_28);
    iVar9 = FUN_8001ffb4(0xaf7);
    if (((iVar9 == 0) || (iVar9 = FUN_8012ebc8(), iVar9 == -1)) && (local_28[0] != 0xaf7)) {
      FUN_8002b6d8(iVar4,0,0,0,0,2);
    }
    else {
      FUN_8002b6d8(iVar4,0,0,0,0,4);
    }
    iVar9 = FUN_80037fa4(iVar4,0xaf7);
    if (iVar9 == 0) {
      if ((*(char *)((int)puVar5 + 0x346) != '\0') && (*(short *)(iVar4 + 0xa0) != 2)) {
        FUN_8002f574(iVar4,0x78);
        FUN_80030334((double)FLOAT_803e6aa8,iVar4,2,0);
        puVar5[0xa8] = (uint)FLOAT_803e6aac;
      }
      iVar9 = FUN_80080150(iVar10 + 0xc2c);
      if (iVar9 == 0) {
        iVar9 = FUN_8002b9ec();
        dVar11 = (double)FUN_80021704(iVar9 + 0x18,iVar4 + 0x18);
        if (((double)FLOAT_803e6aa4 < dVar11) && (iVar4 = FUN_80080100(500), iVar4 != 0)) {
          iVar9 = FUN_800221a0(0,100);
          iVar4 = 0;
          for (piVar6 = &DAT_8032ab3c; *piVar6 < iVar9; piVar6 = piVar6 + 1) {
            iVar9 = iVar9 - (&DAT_8032ab3c)[iVar4];
            iVar4 = iVar4 + 1;
          }
          *(char *)(iVar10 + 0xc42) = (char)iVar4;
          *(byte *)(iVar10 + 0x9fd) = *(byte *)(iVar10 + 0x9fd) | 1;
          FUN_80080178(iVar10 + 0xc2c,0x14);
        }
      }
      else {
        iVar9 = FUN_800801a8(iVar10 + 0xc2c);
        if (iVar9 != 0) {
          *(undefined *)(iVar10 + 0xc4b) = 0xff;
          (**(code **)(*DAT_803dca54 + 0x48))
                    ((&DAT_8032ab30)[*(byte *)(iVar10 + 0xc42)],iVar4,0xffffffff);
        }
      }
      uVar3 = 0;
    }
    else {
      iVar9 = FUN_8001ffb4(0x3f0);
      iVar2 = FUN_8001ffb4(0xaf7);
      FUN_800200e8(0x3f0,iVar9 + iVar2);
      FUN_800200e8(0xaf7,0);
      iVar9 = FUN_80080100(5 - (iVar9 + iVar2));
      if (iVar9 == 0) {
        *(undefined *)(iVar10 + 0xc4b) = 9;
      }
      else {
        *(undefined *)(iVar10 + 0xc4b) = 2;
      }
      FUN_8003aa40(iVar4);
      FUN_8002f574(iVar4,0);
      FUN_80030334((double)FLOAT_803e6aa8,iVar4,0,0);
      FUN_80035f00(iVar4);
      FUN_8002b6d8(iVar4,0,0,0,0,2);
      (**(code **)(*DAT_803dca54 + 0x48))(1,iVar4,0xffffffff);
      uVar3 = 0;
    }
  }
LAB_8021d540:
  FUN_80286120(uVar3);
  return;
}

