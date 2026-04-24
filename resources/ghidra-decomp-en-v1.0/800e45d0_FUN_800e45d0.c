// Function: FUN_800e45d0
// Entry: 800e45d0
// Size: 496 bytes

void FUN_800e45d0(undefined4 param_1,undefined4 param_2,float *param_3,float *param_4)

{
  uint *puVar1;
  undefined4 uVar2;
  float *pfVar3;
  int *piVar4;
  int iVar5;
  int iVar6;
  int iVar7;
  int iVar8;
  int iVar9;
  float *pfVar10;
  float *pfVar11;
  int *piVar12;
  uint uVar13;
  int iVar14;
  undefined8 uVar15;
  int local_28 [10];
  
  uVar15 = FUN_802860d8();
  pfVar3 = (float *)uVar15;
  iVar5 = 0;
  piVar4 = local_28;
  iVar14 = 4;
  pfVar10 = param_4;
  pfVar11 = param_3;
  piVar12 = piVar4;
  do {
    puVar1 = (uint *)((ulonglong)uVar15 >> 0x20);
    uVar13 = *puVar1;
    if ((int)uVar13 < 0) {
      iVar9 = 0;
    }
    else {
      iVar8 = DAT_803dd478 + -1;
      iVar6 = 0;
      while (iVar6 <= iVar8) {
        iVar7 = iVar8 + iVar6 >> 1;
        iVar9 = (&DAT_803a17e8)[iVar7];
        if (*(uint *)(iVar9 + 0x14) < uVar13) {
          iVar6 = iVar7 + 1;
        }
        else {
          if (*(uint *)(iVar9 + 0x14) <= uVar13) goto LAB_800e4670;
          iVar8 = iVar7 + -1;
        }
      }
      iVar9 = 0;
    }
LAB_800e4670:
    *piVar12 = iVar9;
    iVar6 = *piVar12;
    if (iVar6 != 0) {
      *(undefined4 *)uVar15 = *(undefined4 *)(iVar6 + 8);
      *pfVar11 = *(float *)(iVar6 + 0xc);
      *pfVar10 = *(float *)(iVar6 + 0x10);
      iVar5 = iVar5 + 1;
    }
    piVar12 = piVar12 + 1;
    uVar15 = CONCAT44(puVar1 + 1,(undefined4 *)uVar15 + 1);
    pfVar11 = pfVar11 + 1;
    pfVar10 = pfVar10 + 1;
    iVar14 = iVar14 + -1;
    if (iVar14 == 0) {
      if (((iVar5 < 2) || (local_28[1] == 0)) || (local_28[2] == 0)) {
        uVar2 = 0;
      }
      else {
        iVar5 = 0;
        iVar14 = 4;
        do {
          if (*piVar4 == 0) {
            if (iVar5 == 0) {
              *pfVar3 = *(float *)(local_28[1] + 8) +
                        (*(float *)(local_28[1] + 8) - *(float *)(local_28[2] + 8));
              *param_3 = *(float *)(local_28[1] + 0xc) +
                         (*(float *)(local_28[1] + 0xc) - *(float *)(local_28[2] + 0xc));
              *param_4 = *(float *)(local_28[1] + 0x10) +
                         (*(float *)(local_28[1] + 0x10) - *(float *)(local_28[2] + 0x10));
            }
            else if (iVar5 == 3) {
              *pfVar3 = *(float *)(local_28[2] + 8) +
                        (*(float *)(local_28[2] + 8) - *(float *)(local_28[1] + 8));
              *param_3 = *(float *)(local_28[2] + 0xc) +
                         (*(float *)(local_28[2] + 0xc) - *(float *)(local_28[1] + 0xc));
              *param_4 = *(float *)(local_28[2] + 0x10) +
                         (*(float *)(local_28[2] + 0x10) - *(float *)(local_28[1] + 0x10));
            }
          }
          piVar4 = piVar4 + 1;
          pfVar3 = pfVar3 + 1;
          param_3 = param_3 + 1;
          param_4 = param_4 + 1;
          iVar5 = iVar5 + 1;
          iVar14 = iVar14 + -1;
        } while (iVar14 != 0);
        uVar2 = 1;
      }
      FUN_80286124(uVar2);
      return;
    }
  } while( true );
}

