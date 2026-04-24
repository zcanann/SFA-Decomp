// Function: FUN_800e4854
// Entry: 800e4854
// Size: 496 bytes

void FUN_800e4854(undefined4 param_1,undefined4 param_2,float *param_3,float *param_4)

{
  uint *puVar1;
  float *pfVar2;
  int *piVar3;
  int iVar4;
  int iVar5;
  int iVar6;
  int iVar7;
  int iVar8;
  float *pfVar9;
  float *pfVar10;
  int *piVar11;
  uint uVar12;
  int iVar13;
  undefined8 uVar14;
  int local_28 [10];
  
  uVar14 = FUN_8028683c();
  pfVar2 = (float *)uVar14;
  iVar4 = 0;
  piVar3 = local_28;
  iVar13 = 4;
  pfVar9 = param_4;
  pfVar10 = param_3;
  piVar11 = piVar3;
  do {
    puVar1 = (uint *)((ulonglong)uVar14 >> 0x20);
    uVar12 = *puVar1;
    if ((int)uVar12 < 0) {
      iVar8 = 0;
    }
    else {
      iVar7 = DAT_803de0f0 + -1;
      iVar5 = 0;
      while (iVar5 <= iVar7) {
        iVar6 = iVar7 + iVar5 >> 1;
        iVar8 = (&DAT_803a2448)[iVar6];
        if (*(uint *)(iVar8 + 0x14) < uVar12) {
          iVar5 = iVar6 + 1;
        }
        else {
          if (*(uint *)(iVar8 + 0x14) <= uVar12) goto LAB_800e48f4;
          iVar7 = iVar6 + -1;
        }
      }
      iVar8 = 0;
    }
LAB_800e48f4:
    *piVar11 = iVar8;
    iVar5 = *piVar11;
    if (iVar5 != 0) {
      *(undefined4 *)uVar14 = *(undefined4 *)(iVar5 + 8);
      *pfVar10 = *(float *)(iVar5 + 0xc);
      *pfVar9 = *(float *)(iVar5 + 0x10);
      iVar4 = iVar4 + 1;
    }
    piVar11 = piVar11 + 1;
    uVar14 = CONCAT44(puVar1 + 1,(undefined4 *)uVar14 + 1);
    pfVar10 = pfVar10 + 1;
    pfVar9 = pfVar9 + 1;
    iVar13 = iVar13 + -1;
    if (iVar13 == 0) {
      if (((1 < iVar4) && (local_28[1] != 0)) && (local_28[2] != 0)) {
        iVar4 = 0;
        iVar13 = 4;
        do {
          if (*piVar3 == 0) {
            if (iVar4 == 0) {
              *pfVar2 = *(float *)(local_28[1] + 8) +
                        (*(float *)(local_28[1] + 8) - *(float *)(local_28[2] + 8));
              *param_3 = *(float *)(local_28[1] + 0xc) +
                         (*(float *)(local_28[1] + 0xc) - *(float *)(local_28[2] + 0xc));
              *param_4 = *(float *)(local_28[1] + 0x10) +
                         (*(float *)(local_28[1] + 0x10) - *(float *)(local_28[2] + 0x10));
            }
            else if (iVar4 == 3) {
              *pfVar2 = *(float *)(local_28[2] + 8) +
                        (*(float *)(local_28[2] + 8) - *(float *)(local_28[1] + 8));
              *param_3 = *(float *)(local_28[2] + 0xc) +
                         (*(float *)(local_28[2] + 0xc) - *(float *)(local_28[1] + 0xc));
              *param_4 = *(float *)(local_28[2] + 0x10) +
                         (*(float *)(local_28[2] + 0x10) - *(float *)(local_28[1] + 0x10));
            }
          }
          piVar3 = piVar3 + 1;
          pfVar2 = pfVar2 + 1;
          param_3 = param_3 + 1;
          param_4 = param_4 + 1;
          iVar4 = iVar4 + 1;
          iVar13 = iVar13 + -1;
        } while (iVar13 != 0);
      }
      FUN_80286888();
      return;
    }
  } while( true );
}

