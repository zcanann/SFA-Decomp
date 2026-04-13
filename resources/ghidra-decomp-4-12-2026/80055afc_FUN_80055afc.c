// Function: FUN_80055afc
// Entry: 80055afc
// Size: 932 bytes

/* WARNING: Removing unreachable block (ram,0x80055e80) */
/* WARNING: Removing unreachable block (ram,0x80055e78) */
/* WARNING: Removing unreachable block (ram,0x80055e70) */
/* WARNING: Removing unreachable block (ram,0x80055b1c) */
/* WARNING: Removing unreachable block (ram,0x80055b14) */
/* WARNING: Removing unreachable block (ram,0x80055b0c) */

void FUN_80055afc(undefined4 param_1,undefined4 param_2,undefined4 param_3)

{
  bool bVar1;
  int iVar2;
  float fVar3;
  float fVar4;
  float fVar5;
  bool bVar6;
  int iVar7;
  uint uVar8;
  int *piVar9;
  int iVar10;
  char extraout_r4;
  char cVar11;
  double dVar12;
  double in_f29;
  double in_f30;
  double in_f31;
  undefined8 local_58;
  
  iVar7 = FUN_80286840();
  bVar1 = *(int *)(iVar7 + 0x14) == 0x49054;
  uVar8 = (**(code **)(*DAT_803dd72c + 0x40))(param_3);
  uVar8 = uVar8 & 0xff;
  if (uVar8 == 0xffffffff) {
    bVar6 = false;
    goto LAB_80055bd4;
  }
  if (uVar8 == 0) {
LAB_80055bd0:
    bVar6 = true;
  }
  else if (uVar8 < 9) {
    if (((int)(uint)*(byte *)(iVar7 + 3) >> (uVar8 - 1 & 0x3f) & 1U) == 0) goto LAB_80055bd0;
    bVar6 = false;
  }
  else {
    if (((int)(uint)*(byte *)(iVar7 + 5) >> (0x10 - uVar8 & 0x3f) & 1U) == 0) goto LAB_80055bd0;
    bVar6 = false;
  }
LAB_80055bd4:
  if (bVar6) {
    if ((*(byte *)(iVar7 + 4) & 1) == 0) {
      if ((*(byte *)(iVar7 + 4) & 2) == 0) {
        if (extraout_r4 == '\0') {
          dVar12 = (double)FUN_802925a0();
          iVar10 = (int)dVar12;
          dVar12 = (double)FUN_802925a0();
          iVar2 = (int)dVar12;
          if ((((iVar10 < 0) || (iVar2 < 0)) || (0xf < iVar10)) || (0xf < iVar2)) {
            if (bVar1) {
              FUN_8007d858();
            }
            goto LAB_80055e70;
          }
          bVar6 = false;
          piVar9 = &DAT_80382f14;
          for (cVar11 = '\0'; cVar11 < '\x05'; cVar11 = cVar11 + '\x01') {
            if (-1 < *(char *)(iVar10 + iVar2 * 0x10 + *piVar9)) {
              bVar6 = true;
            }
            piVar9 = piVar9 + 1;
          }
          if (!bVar6) {
            if (bVar1) {
              FUN_8007d858();
            }
            goto LAB_80055e70;
          }
        }
        if ((*(byte *)(iVar7 + 4) & 0x20) == 0) {
          bVar6 = false;
          if (((*(byte *)(iVar7 + 4) & 4) == 0) || (extraout_r4 != '\0')) {
            bVar6 = true;
          }
          else {
            iVar10 = FUN_8002bac4();
            if (iVar10 == 0) {
              bVar6 = true;
            }
            else {
              in_f29 = (double)*(float *)(iVar10 + 0x18);
              in_f31 = (double)*(float *)(iVar10 + 0x1c);
              in_f30 = (double)*(float *)(iVar10 + 0x20);
            }
          }
          if (bVar6) {
            iVar10 = (int)extraout_r4;
            in_f29 = (double)(float)(&DAT_803872a8)[iVar10 * 4];
            in_f31 = (double)(float)(&DAT_803872ac)[iVar10 * 4];
            in_f30 = (double)(float)(&DAT_803872b0)[iVar10 * 4];
          }
          local_58 = (double)CONCAT44(0x43300000,(uint)*(byte *)(iVar7 + 6) << 3 ^ 0x80000000);
          fVar3 = (float)(in_f29 - (double)*(float *)(iVar7 + 8));
          fVar4 = (float)(in_f31 - (double)*(float *)(iVar7 + 0xc));
          fVar5 = (float)(in_f30 - (double)*(float *)(iVar7 + 0x10));
          if ((float)(local_58 - DOUBLE_803df840) * (float)(local_58 - DOUBLE_803df840) <=
              fVar5 * fVar5 + fVar4 * fVar4 + fVar3 * fVar3) {
            if (bVar1) {
              FUN_8007d858();
            }
          }
          else if (bVar1) {
            FUN_8007d858();
          }
        }
        else if (bVar1) {
          FUN_8007d858();
        }
      }
      else if (bVar1) {
        FUN_8007d858();
      }
    }
    else if (bVar1) {
      FUN_8007d858();
    }
  }
LAB_80055e70:
  FUN_8028688c();
  return;
}

