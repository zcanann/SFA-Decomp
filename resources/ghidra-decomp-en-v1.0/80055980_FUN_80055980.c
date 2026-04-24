// Function: FUN_80055980
// Entry: 80055980
// Size: 932 bytes

/* WARNING: Removing unreachable block (ram,0x80055cfc) */
/* WARNING: Removing unreachable block (ram,0x80055cf4) */
/* WARNING: Removing unreachable block (ram,0x80055d04) */

void FUN_80055980(undefined4 param_1,undefined4 param_2,undefined4 param_3)

{
  bool bVar1;
  int iVar2;
  float fVar3;
  float fVar4;
  float fVar5;
  bool bVar6;
  int iVar7;
  uint uVar8;
  undefined4 uVar9;
  int *piVar10;
  int iVar11;
  char extraout_r4;
  char cVar12;
  undefined4 uVar13;
  double dVar14;
  double in_f29;
  double in_f30;
  double in_f31;
  float local_68 [2];
  longlong local_60;
  double local_58;
  undefined auStack40 [16];
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar13 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,SUB84(in_f31,0),0);
  __psq_st0(auStack24,(int)((ulonglong)in_f30 >> 0x20),0);
  __psq_st1(auStack24,SUB84(in_f30,0),0);
  __psq_st0(auStack40,(int)((ulonglong)in_f29 >> 0x20),0);
  __psq_st1(auStack40,SUB84(in_f29,0),0);
  iVar7 = FUN_802860dc();
  bVar1 = *(int *)(iVar7 + 0x14) == 0x49054;
  uVar8 = (**(code **)(*DAT_803dcaac + 0x40))(param_3);
  uVar8 = uVar8 & 0xff;
  if (uVar8 == 0xffffffff) {
    bVar6 = false;
    goto LAB_80055a58;
  }
  if (uVar8 == 0) {
LAB_80055a54:
    bVar6 = true;
  }
  else if (uVar8 < 9) {
    if (((int)(uint)*(byte *)(iVar7 + 3) >> (uVar8 - 1 & 0x3f) & 1U) == 0) goto LAB_80055a54;
    bVar6 = false;
  }
  else {
    if (((int)(uint)*(byte *)(iVar7 + 5) >> (0x10 - uVar8 & 0x3f) & 1U) == 0) goto LAB_80055a54;
    bVar6 = false;
  }
LAB_80055a58:
  if (bVar6) {
    if ((*(byte *)(iVar7 + 4) & 1) == 0) {
      if ((*(byte *)(iVar7 + 4) & 2) == 0) {
        if (extraout_r4 == '\0') {
          dVar14 = (double)FUN_80291e40((double)((*(float *)(iVar7 + 8) - FLOAT_803dcdd8) /
                                                FLOAT_803debb4));
          iVar11 = (int)dVar14;
          local_60 = (longlong)iVar11;
          dVar14 = (double)FUN_80291e40((double)((*(float *)(iVar7 + 0x10) - FLOAT_803dcddc) /
                                                FLOAT_803debb4));
          iVar2 = (int)dVar14;
          local_58 = (double)(longlong)iVar2;
          if ((((iVar11 < 0) || (iVar2 < 0)) || (0xf < iVar11)) || (0xf < iVar2)) {
            if (bVar1) {
              FUN_8007d6dc(s_LOAD_FAIL__Outside_map_x__f_y__f_8030e6b0,iVar7 + 8,iVar7 + 0xc,
                           iVar7 + 0x10);
            }
            uVar9 = 0;
            goto LAB_80055cf4;
          }
          bVar6 = false;
          piVar10 = &DAT_803822b4;
          for (cVar12 = '\0'; cVar12 < '\x05'; cVar12 = cVar12 + '\x01') {
            if (-1 < *(char *)(iVar11 + iVar2 * 0x10 + *piVar10)) {
              bVar6 = true;
            }
            piVar10 = piVar10 + 1;
          }
          if (!bVar6) {
            if (bVar1) {
              FUN_8007d6dc(s_LOAD_FAIL__No_block_8030e6d8);
            }
            uVar9 = 0;
            goto LAB_80055cf4;
          }
        }
        if ((*(byte *)(iVar7 + 4) & 0x20) == 0) {
          bVar6 = false;
          if (((*(byte *)(iVar7 + 4) & 4) == 0) || (extraout_r4 != '\0')) {
            bVar6 = true;
          }
          else {
            iVar11 = FUN_8002b9ec();
            if (iVar11 == 0) {
              bVar6 = true;
            }
            else {
              in_f29 = (double)*(float *)(iVar11 + 0x18);
              in_f31 = (double)*(float *)(iVar11 + 0x1c);
              in_f30 = (double)*(float *)(iVar11 + 0x20);
            }
          }
          if (bVar6) {
            iVar11 = (int)extraout_r4;
            in_f29 = (double)(float)(&DAT_80386648)[iVar11 * 4];
            in_f31 = (double)(float)(&DAT_8038664c)[iVar11 * 4];
            in_f30 = (double)(float)(&DAT_80386650)[iVar11 * 4];
          }
          local_58 = (double)CONCAT44(0x43300000,(uint)*(byte *)(iVar7 + 6) << 3 ^ 0x80000000);
          fVar3 = (float)(in_f29 - (double)*(float *)(iVar7 + 8));
          fVar4 = (float)(in_f31 - (double)*(float *)(iVar7 + 0xc));
          fVar5 = (float)(in_f30 - (double)*(float *)(iVar7 + 0x10));
          local_68[0] = fVar5 * fVar5 + fVar4 * fVar4 + fVar3 * fVar3;
          if ((float)(local_58 - DOUBLE_803debc0) * (float)(local_58 - DOUBLE_803debc0) <=
              local_68[0]) {
            if (bVar1) {
              FUN_8007d6dc(s_LOAD_FAIL__Out_of_range_8030e724);
            }
            uVar9 = 0;
          }
          else {
            if (bVar1) {
              FUN_8007d6dc(s_LOAD_PASS__In_range__f_8030e70c,local_68);
            }
            uVar9 = 1;
          }
        }
        else {
          if (bVar1) {
            FUN_8007d6dc(s_LOAD_PASS__Block_object_8030e6f0);
          }
          uVar9 = 1;
        }
      }
      else {
        if (bVar1) {
          FUN_8007d6dc(s_LOAD_FAIL__Manual_load_8030e698);
        }
        uVar9 = 0;
      }
    }
    else {
      if (bVar1) {
        FUN_8007d6dc(s_LOAD_PASS__Level_object_8030e67c);
      }
      uVar9 = 1;
    }
  }
  else {
    uVar9 = 0;
  }
LAB_80055cf4:
  __psq_l0(auStack8,uVar13);
  __psq_l1(auStack8,uVar13);
  __psq_l0(auStack24,uVar13);
  __psq_l1(auStack24,uVar13);
  __psq_l0(auStack40,uVar13);
  __psq_l1(auStack40,uVar13);
  FUN_80286128(uVar9);
  return;
}

