// Function: FUN_802a0de0
// Entry: 802a0de0
// Size: 2708 bytes

/* WARNING: Removing unreachable block (ram,0x802a1854) */
/* WARNING: Removing unreachable block (ram,0x802a184c) */
/* WARNING: Removing unreachable block (ram,0x802a1844) */
/* WARNING: Removing unreachable block (ram,0x802a183c) */
/* WARNING: Removing unreachable block (ram,0x802a0e08) */
/* WARNING: Removing unreachable block (ram,0x802a0e00) */
/* WARNING: Removing unreachable block (ram,0x802a0df8) */
/* WARNING: Removing unreachable block (ram,0x802a0df0) */

void FUN_802a0de0(undefined8 param_1,double param_2,double param_3,double param_4,double param_5,
                 undefined8 param_6,undefined8 param_7,undefined8 param_8)

{
  double dVar1;
  double dVar2;
  float fVar3;
  float fVar4;
  bool bVar5;
  bool bVar6;
  bool bVar7;
  bool bVar8;
  uint uVar9;
  int *piVar10;
  uint uVar11;
  uint *puVar12;
  int iVar13;
  float *in_r6;
  int *in_r7;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  short sVar14;
  int iVar15;
  int *piVar16;
  double dVar17;
  double in_f28;
  double dVar18;
  double dVar19;
  double in_f29;
  double in_f30;
  double in_f31;
  double in_ps28_1;
  double in_ps29_1;
  double in_ps30_1;
  double in_ps31_1;
  undefined8 uVar20;
  int aiStack_f0 [2];
  float local_e8;
  float local_e4;
  float local_e0;
  float local_dc;
  float local_d8;
  float local_d4;
  float local_d0;
  float local_cc;
  float afStack_c4 [3];
  float local_b8;
  float local_b4;
  undefined4 local_a8;
  undefined4 local_a4;
  float local_a0;
  undefined4 local_9c;
  float local_88;
  float local_84;
  float local_7c;
  byte local_72;
  longlong local_70;
  float local_38;
  float fStack_34;
  float local_28;
  float fStack_24;
  float local_18;
  float fStack_14;
  float local_8;
  float fStack_4;
  
  local_8 = (float)in_f31;
  fStack_4 = (float)in_ps31_1;
  local_18 = (float)in_f30;
  fStack_14 = (float)in_ps30_1;
  local_28 = (float)in_f29;
  fStack_24 = (float)in_ps29_1;
  local_38 = (float)in_f28;
  fStack_34 = (float)in_ps28_1;
  uVar20 = FUN_80286830();
  piVar10 = (int *)((ulonglong)uVar20 >> 0x20);
  puVar12 = (uint *)uVar20;
  iVar15 = piVar10[0x2e];
  if (*(char *)((int)puVar12 + 0x27a) != '\0') {
    DAT_803dd308 = 0x10;
    FUN_80035f84((int)piVar10);
  }
  iVar13 = piVar10[0x2e];
  *(uint *)(iVar13 + 0x360) = *(uint *)(iVar13 + 0x360) & 0xfffffffd;
  *(uint *)(iVar13 + 0x360) = *(uint *)(iVar13 + 0x360) | 0x2000;
  puVar12[1] = puVar12[1] | 0x100000;
  fVar3 = FLOAT_803e8b3c;
  puVar12[0xa0] = (uint)FLOAT_803e8b3c;
  puVar12[0xa1] = (uint)fVar3;
  *puVar12 = *puVar12 | 0x200000;
  piVar10[9] = (int)fVar3;
  piVar10[0xb] = (int)fVar3;
  puVar12[1] = puVar12[1] | 0x8000000;
  piVar10[10] = (int)fVar3;
  piVar16 = *(int **)(piVar10[0x1f] + *(char *)((int)piVar10 + 0xad) * 4);
  dVar18 = (double)(float)puVar12[0xa8];
  DAT_803dd30a = DAT_803dd308;
  if ((short)DAT_803dd308 < 0x15) {
    if (DAT_803dd308 != 0x10) goto LAB_802a0f50;
    if (*(short *)(piVar10 + 0x28) == 0x66) {
      *(undefined2 *)(iVar15 + 0x5a6) = 0;
      DAT_803dd308 = 0x16;
    }
    else {
      *(undefined2 *)(iVar15 + 0x5a6) = 1;
      DAT_803dd308 = 0x15;
    }
    piVar10[4] = *(int *)(iVar15 + 0x76c);
    dVar18 = (double)FLOAT_803e8c90;
LAB_802a0f14:
    fVar3 = FLOAT_803e8b3c;
    *(float *)(iVar15 + 0x564) = FLOAT_803e8b3c;
    *(float *)(iVar15 + 0x560) = fVar3;
    *(float *)(iVar15 + 0x568) = fVar3;
    FUN_802a1b54((uint)piVar10,(int)puVar12);
    if (FLOAT_803e8b94 < (float)puVar12[0xa6]) {
      in_f31 = (double)(float)piVar10[0x26];
      piVar10[0x26] = (int)FLOAT_803e8b78;
      goto LAB_802a0f50;
    }
  }
  else {
    if ((short)DAT_803dd308 < 0x17) goto LAB_802a0f14;
LAB_802a0f50:
    if (FLOAT_803e8b78 == (float)piVar10[0x26]) {
      param_2 = (double)FLOAT_803e8bc8;
      local_dc = -(float)(param_2 * (double)*(float *)(iVar15 + 0x56c) -
                         (double)*(float *)(iVar15 + 0x768));
      local_d8 = *(float *)(iVar15 + 0x76c);
      local_d4 = -(float)(param_2 * (double)*(float *)(iVar15 + 0x574) -
                         (double)*(float *)(iVar15 + 0x770));
      in_r6 = afStack_c4;
      in_r8 = 1;
      in_r9 = 3;
      in_r10 = 0xff;
      in_r7 = piVar10;
      iVar13 = FUN_80064248(iVar15 + 0x768,&local_dc,(float *)0x3,(int *)in_r6,piVar10,1,3,0xff,0);
      if (iVar13 == 0) {
        iVar13 = 2;
      }
      else {
        piVar10[3] = (int)local_dc;
        piVar10[5] = (int)local_d4;
        *(float *)(iVar15 + 0x54c) = local_7c * (local_84 - local_88) + local_88;
        *(float *)(iVar15 + 0x550) = local_7c * (local_b4 - local_b8) + local_b8;
        *(undefined4 *)(iVar15 + 0x56c) = local_a8;
        *(undefined4 *)(iVar15 + 0x570) = local_a4;
        *(float *)(iVar15 + 0x574) = local_a0;
        *(undefined4 *)(iVar15 + 0x578) = local_9c;
        *(float *)(iVar15 + 0x57c) = -local_a0;
        *(float *)(iVar15 + 0x580) = FLOAT_803e8b3c;
        *(undefined4 *)(iVar15 + 0x584) = local_a8;
        param_5 = (double)local_d4;
        param_4 = (double)*(float *)(iVar15 + 0x584);
        param_3 = (double)local_dc;
        *(float *)(iVar15 + 0x588) =
             -(float)(param_5 * param_4 +
                     (double)(float)(param_3 * (double)*(float *)(iVar15 + 0x57c) +
                                    (double)(local_d8 * *(float *)(iVar15 + 0x580))));
        param_2 = (double)*(float *)(iVar15 + 0x574);
        iVar13 = FUN_80021884();
        *(short *)(iVar15 + 0x478) = (short)iVar13;
        *(undefined2 *)(iVar15 + 0x484) = *(undefined2 *)(iVar15 + 0x478);
        if ((local_72 & 4) == 0) {
          if ((local_72 & 8) == 0) {
            if ((local_72 & 2) == 0) {
              iVar13 = 3;
            }
            else {
              iVar13 = 2;
            }
          }
          else {
            iVar13 = 1;
          }
        }
        else {
          iVar13 = 0;
        }
      }
      if ((DAT_803dd308 != 0x15) && (DAT_803dd308 != 0x16)) {
        piVar10[4] = *(int *)(iVar15 + 0x76c);
      }
      if ((float)puVar12[0xa6] <= FLOAT_803e8b94) {
        piVar10[4] = *(int *)(iVar15 + 0x76c);
        if (*(short *)(iVar15 + 0x5a6) == 0) {
          DAT_803dd308 = 0x16;
        }
        else {
          DAT_803dd308 = 0x15;
        }
        dVar18 = (double)FLOAT_803e8c90;
      }
      else {
        dVar18 = -(double)(float)puVar12[0xa3];
        uVar11 = FUN_80021884();
        uVar11 = (uVar11 & 0xffff) + 0x1000 >> 0xd;
        DAT_803dd308 = (ushort)uVar11 & 7;
        DAT_803dd30a = 0xffff;
        if ((DAT_803dd308 == 4) || ((uVar11 & 7) == 0)) {
          *(ushort *)(iVar15 + 0x5a6) = *(ushort *)(iVar15 + 0x5a6) ^ 1;
        }
        bVar5 = false;
        bVar6 = false;
        bVar7 = false;
        bVar8 = false;
        switch(DAT_803dd308) {
        case 0:
          bVar6 = true;
          break;
        case 1:
          bVar6 = true;
          bVar8 = true;
          break;
        case 2:
          bVar8 = true;
          break;
        case 3:
          bVar5 = true;
          bVar8 = true;
          break;
        case 4:
          bVar5 = true;
          break;
        case 5:
          bVar5 = true;
          bVar7 = true;
          break;
        case 6:
          bVar7 = true;
          break;
        case 7:
          bVar6 = true;
          bVar7 = true;
        }
        if (*(short *)(iVar15 + 0x5a6) != 0) {
          DAT_803dd308 = DAT_803dd308 + 8;
        }
        if (bVar5) {
          dVar17 = (double)(*(float *)(iVar15 + 0x54c) - *(float *)(iVar15 + 0x76c));
          dVar18 = (double)DAT_803dbc18;
          if (dVar18 < (double)FLOAT_803e8b3c) {
            dVar18 = -dVar18;
          }
          param_3 = (double)DAT_803dbc1c;
          if (param_3 < (double)FLOAT_803e8b3c) {
            param_3 = -param_3;
          }
          if ((dVar17 < param_3) && ((iVar13 == 0 || (iVar13 == 3)))) {
            fVar3 = (float)(dVar17 - dVar18) / (float)(param_3 - dVar18);
            fVar4 = FLOAT_803e8b3c;
            if ((FLOAT_803e8b3c <= fVar3) && (fVar4 = fVar3, FLOAT_803e8b78 < fVar3)) {
              fVar4 = FLOAT_803e8b78;
            }
            local_70 = (longlong)(int)(FLOAT_803e8c44 * fVar4);
            *(short *)(iVar15 + 0x5a4) = (short)(int)(FLOAT_803e8c44 * fVar4);
            *(float *)(iVar15 + 0x560) = fVar4;
            puVar12[0xc2] = (uint)FUN_802a0730;
            goto LAB_802a183c;
          }
        }
        else if (bVar6) {
          dVar17 = (double)(*(float *)(iVar15 + 0x76c) - *(float *)(iVar15 + 0x550));
          dVar18 = (double)DAT_803dbc20;
          if (dVar18 < (double)FLOAT_803e8b3c) {
            dVar18 = -dVar18;
          }
          param_3 = (double)DAT_803dbc24;
          if (param_3 < (double)FLOAT_803e8b3c) {
            param_3 = -param_3;
          }
          if ((dVar17 < param_3) && ((iVar13 == 1 || (iVar13 == 3)))) {
            fVar3 = (float)(dVar17 - dVar18) / (float)(param_3 - dVar18);
            fVar4 = FLOAT_803e8b3c;
            if ((FLOAT_803e8b3c <= fVar3) && (fVar4 = fVar3, FLOAT_803e8b78 < fVar3)) {
              fVar4 = FLOAT_803e8b78;
            }
            local_70 = (longlong)(int)(FLOAT_803e8c44 * fVar4);
            *(short *)(iVar15 + 0x5a4) = (short)(int)(FLOAT_803e8c44 * fVar4);
            *(float *)(iVar15 + 0x560) = fVar4;
            puVar12[0xc2] = (uint)FUN_802a0730;
            goto LAB_802a183c;
          }
        }
        FUN_8002f334((double)FLOAT_803e8b3c,dVar18,param_3,param_4,param_5,param_6,param_7,param_8,
                     (int)piVar10,(int)*(short *)(&DAT_80333ba8 + (short)DAT_803dd308 * 2),1);
        param_2 = (double)(float)piVar10[2];
        in_r6 = &local_d0;
        in_r7 = aiStack_f0;
        FUN_80027ec4((double)FLOAT_803e8b78,param_2,piVar16,1,0,in_r6,(short *)in_r7);
        *(undefined2 *)((int)piVar10 + 0xa2) = 0xffff;
        *(float *)(iVar15 + 0x564) = *(float *)(iVar15 + 0x57c) * -local_d0;
        *(float *)(iVar15 + 0x560) = local_cc;
        *(float *)(iVar15 + 0x568) = *(float *)(iVar15 + 0x584) * -local_d0;
        if ((!bVar5) && (!bVar6)) {
          *(float *)(iVar15 + 0x560) = FLOAT_803e8b3c;
        }
        fVar3 = FLOAT_803e8b3c;
        if ((!bVar7) && (!bVar8)) {
          *(float *)(iVar15 + 0x564) = FLOAT_803e8b3c;
          *(float *)(iVar15 + 0x568) = fVar3;
        }
        uVar11 = 0;
        if (FLOAT_803e8b3c <= local_d0) {
          fVar3 = -*(float *)(iVar15 + 0x57c);
          fVar4 = -*(float *)(iVar15 + 0x584);
        }
        else {
          fVar3 = *(float *)(iVar15 + 0x57c);
          fVar4 = *(float *)(iVar15 + 0x584);
        }
        dVar17 = (double)(FLOAT_803e8c94 * fVar3);
        dVar18 = (double)(FLOAT_803e8c94 * fVar4);
        if ((bVar5) || (bVar6)) {
          param_2 = (double)local_cc;
          local_d8 = (float)((double)*(float *)(iVar15 + 0x76c) + param_2);
          if ((double)FLOAT_803e8b3c <= param_2) {
            local_d8 = local_d8 + FLOAT_803e8be8;
          }
          else {
            local_d8 = local_d8 - FLOAT_803e8be8;
          }
          dVar19 = (double)FLOAT_803e8bc8;
          for (sVar14 = 0; sVar14 < 2; sVar14 = sVar14 + 1) {
            if (sVar14 == 0) {
              dVar1 = (double)*(float *)(iVar15 + 0x768) - dVar17;
              dVar2 = (double)*(float *)(iVar15 + 0x770) - dVar18;
            }
            else {
              dVar1 = (double)*(float *)(iVar15 + 0x768) + dVar17;
              dVar2 = (double)*(float *)(iVar15 + 0x770) + dVar18;
            }
            local_d4 = (float)dVar2;
            local_dc = (float)dVar1;
            local_e8 = -(float)(dVar19 * (double)*(float *)(iVar15 + 0x56c) - (double)local_dc);
            local_e4 = local_d8;
            local_e0 = -(float)(dVar19 * (double)*(float *)(iVar15 + 0x574) - (double)local_d4);
            in_r6 = (float *)0x0;
            in_r8 = 1;
            in_r9 = 3;
            in_r10 = 0xff;
            in_r7 = piVar10;
            iVar13 = FUN_80064248(&local_dc,&local_e8,(float *)0x3,(int *)0x0,piVar10,1,3,0xff,0);
            if (iVar13 != 0) {
              uVar11 = uVar11 | 1 << (int)sVar14;
            }
          }
        }
        else {
          uVar11 = 3;
        }
        if ((bVar7) || (bVar8)) {
          local_dc = (float)(dVar17 + (double)(*(float *)(iVar15 + 0x768) +
                                              *(float *)(iVar15 + 0x564)));
          local_d4 = (float)(dVar18 + (double)(*(float *)(iVar15 + 0x770) +
                                              *(float *)(iVar15 + 0x568)));
          dVar18 = (double)FLOAT_803e8bc8;
          for (sVar14 = 0; sVar14 < 2; sVar14 = sVar14 + 1) {
            if (sVar14 == 0) {
              local_d8 = *(float *)(iVar15 + 0x76c) - FLOAT_803e8be8;
            }
            else {
              local_d8 = FLOAT_803e8be8 + *(float *)(iVar15 + 0x76c);
            }
            local_e8 = -(float)(dVar18 * (double)*(float *)(iVar15 + 0x56c) - (double)local_dc);
            local_e4 = local_d8;
            local_e0 = -(float)(dVar18 * (double)*(float *)(iVar15 + 0x574) - (double)local_d4);
            in_r6 = (float *)0x0;
            in_r8 = 1;
            in_r9 = 3;
            in_r10 = 0xff;
            in_r7 = piVar10;
            iVar13 = FUN_80064248(&local_dc,&local_e8,(float *)0x3,(int *)0x0,piVar10,1,3,0xff,0);
            if (iVar13 != 0) {
              uVar11 = uVar11 | 1 << sVar14 + 2;
            }
          }
        }
        else {
          uVar11 = uVar11 | 0xc;
        }
        fVar3 = FLOAT_803e8b3c;
        dVar18 = (double)FLOAT_803e8c64;
        if (uVar11 != 0xf) {
          *(float *)(iVar15 + 0x564) = FLOAT_803e8b3c;
          *(float *)(iVar15 + 0x560) = fVar3;
          *(float *)(iVar15 + 0x568) = fVar3;
          iVar13 = (int)(short)DAT_803dd308;
          if ((iVar13 == 4) || (iVar13 == 0)) {
LAB_802a16dc:
            *(ushort *)(iVar15 + 0x5a6) = *(ushort *)(iVar15 + 0x5a6) ^ 1;
          }
          else {
            uVar11 = countLeadingZeros(0xc - iVar13);
            uVar9 = countLeadingZeros(8 - iVar13);
            if (uVar11 >> 5 != 0 || uVar9 >> 5 != 0) goto LAB_802a16dc;
          }
          if (*(short *)(iVar15 + 0x5a6) == 0) {
            DAT_803dd308 = 0x16;
          }
          else {
            DAT_803dd308 = 0x15;
          }
          if ((*(short *)(piVar10 + 0x28) == DAT_80333bd2) ||
             (*(short *)(piVar10 + 0x28) == DAT_80333bd4)) {
            DAT_803dd30a = DAT_803dd308;
            piVar10[0x26] = (int)(float)in_f31;
          }
          dVar18 = (double)FLOAT_803e8c90;
        }
      }
    }
    if ((DAT_803dd308 != 0x15) && (DAT_803dd308 != 0x16)) {
      param_2 = (double)(float)puVar12[0xa6];
      if ((double)FLOAT_803e8b3c <= dVar18) {
        if ((double)FLOAT_803e8b3c < dVar18) {
          dVar18 = (double)(float)((double)FLOAT_803e8c9c * param_2 + (double)FLOAT_803e8c98);
        }
      }
      else {
        dVar18 = -(double)(float)((double)FLOAT_803e8c9c * param_2 + (double)FLOAT_803e8c98);
      }
    }
    FUN_802a1b54((uint)piVar10,(int)puVar12);
  }
  puVar12[0xa8] = (uint)(float)dVar18;
  if ((int)(short)DAT_803dd30a != (int)(short)DAT_803dd308) {
    FUN_8003042c((double)FLOAT_803e8b3c,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 piVar10,(int)*(short *)(&DAT_80333ba8 + (short)DAT_803dd308 * 2),1,in_r6,in_r7,
                 in_r8,in_r9,in_r10);
  }
  fVar3 = (float)piVar10[0x26];
  (**(code **)(*DAT_803dd6d0 + 0x2c))
            ((double)(*(float *)(iVar15 + 0x564) * fVar3 + (float)piVar10[3]),
             (double)(*(float *)(iVar15 + 0x560) * fVar3 + (float)piVar10[4]),
             (double)(*(float *)(iVar15 + 0x568) * fVar3 + (float)piVar10[5]));
  FUN_802abd04((int)piVar10,iVar15,5);
LAB_802a183c:
  FUN_8028687c();
  return;
}

