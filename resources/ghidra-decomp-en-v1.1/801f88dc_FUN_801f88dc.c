// Function: FUN_801f88dc
// Entry: 801f88dc
// Size: 3860 bytes

/* WARNING: Removing unreachable block (ram,0x801f97d0) */
/* WARNING: Removing unreachable block (ram,0x801f97c8) */
/* WARNING: Removing unreachable block (ram,0x801f88f4) */
/* WARNING: Removing unreachable block (ram,0x801f88ec) */

void FUN_801f88dc(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)

{
  ushort uVar1;
  float fVar2;
  float fVar3;
  ushort *puVar4;
  int iVar5;
  int iVar6;
  uint uVar7;
  char cVar8;
  undefined4 *puVar9;
  int in_r6;
  undefined4 in_r7;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  uint uVar10;
  int iVar11;
  int iVar12;
  undefined8 uVar13;
  double dVar14;
  double dVar15;
  double dVar16;
  double dVar17;
  double dVar18;
  double in_f30;
  double dVar19;
  double in_f31;
  double in_ps30_1;
  double in_ps31_1;
  float local_48;
  undefined4 *local_44;
  undefined4 local_40;
  uint uStack_3c;
  float local_18;
  float fStack_14;
  float local_8;
  float fStack_4;
  
  local_8 = (float)in_f31;
  fStack_4 = (float)in_ps31_1;
  local_18 = (float)in_f30;
  fStack_14 = (float)in_ps30_1;
  puVar4 = (ushort *)FUN_8028683c();
  iVar12 = *(int *)(puVar4 + 0x5c);
  iVar11 = 0;
  dVar19 = (double)FLOAT_803e6c4c;
  uVar10 = 0;
  local_44 = (undefined4 *)0x0;
  local_48 = FLOAT_803e6c54;
  if ((*(ushort *)(iVar12 + 0x294) & 0x10) == 0) {
    iVar5 = FUN_8002bac4();
  }
  else {
    iVar5 = FUN_80036f50(10,puVar4,&local_48);
  }
  if (iVar5 != 0) {
    uStack_3c = FUN_80020078(0x789);
    local_40 = 0x43300000;
    FLOAT_803dcd98 =
         FLOAT_803e6c58 * (float)((double)CONCAT44(0x43300000,uStack_3c) - DOUBLE_803e6cb8) +
         FLOAT_803e6c58;
    if (*(char *)(iVar12 + 0x296) == '\x06') {
      *(byte *)((int)puVar4 + 0xaf) = *(byte *)((int)puVar4 + 0xaf) | 8;
      if (puVar4[0x50] != 1) {
        FUN_8003042c((double)FLOAT_803e6c48,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                     puVar4,1,0,in_r6,in_r7,in_r8,in_r9,in_r10);
        FUN_8000bb38((uint)puVar4,0x73);
      }
      if (FLOAT_803e6c5c < *(float *)(puVar4 + 0x4c)) {
        *(float *)(puVar4 + 4) = *(float *)(puVar4 + 4) * FLOAT_803e6c60;
      }
      uStack_3c = (uint)DAT_803dc070;
      local_40 = 0x43300000;
      dVar19 = (double)(float)((double)CONCAT44(0x43300000,uStack_3c) - DOUBLE_803e6cb8);
      iVar11 = FUN_8002fb40((double)FLOAT_803e6c64,dVar19);
      if (iVar11 != 0) {
        uVar10 = (uint)*(short *)(iVar12 + 0x292);
        if ((uVar10 != 0) && (uVar10 != 0xffffffff)) {
          uVar10 = FUN_80020078(uVar10);
          FUN_800201ac((int)*(short *)(iVar12 + 0x292),uVar10 + 1);
        }
        if (*(int *)(*(int *)(puVar4 + 0x26) + 0x14) == 0) {
          uVar13 = FUN_80035ff8((int)puVar4);
          FUN_8002cc9c(uVar13,dVar19,param_3,param_4,param_5,param_6,param_7,param_8,(int)puVar4);
        }
        else {
          FUN_8002cf80((int)puVar4);
          FUN_80035ff8((int)puVar4);
          FUN_8003709c((int)puVar4,3);
          puVar4[3] = puVar4[3] | 0x4000;
        }
      }
    }
    else {
      if ((*(ushort *)(iVar12 + 0x294) & 8) != 0) {
        iVar6 = FUN_80080434((float *)(iVar12 + 0x28a));
        if (iVar6 != 0) {
          iVar11 = 0;
          do {
            (**(code **)(*DAT_803dd708 + 8))(puVar4,0x1a3,0,0,0xffffffff,0);
            iVar11 = iVar11 + 1;
          } while (iVar11 < 0x1e);
          FUN_80080404((float *)(iVar12 + 0x28c),100);
          goto LAB_801f97c8;
        }
        iVar6 = FUN_80080434((float *)(iVar12 + 0x28c));
        if (iVar6 != 0) {
          *(byte *)((int)puVar4 + 0xaf) = *(byte *)((int)puVar4 + 0xaf) | 8;
          if (*(int *)(*(int *)(puVar4 + 0x26) + 0x14) == 0) {
            uVar13 = FUN_80035ff8((int)puVar4);
            FUN_8002cc9c(uVar13,param_2,param_3,param_4,param_5,param_6,param_7,param_8,(int)puVar4)
            ;
          }
          else {
            FUN_8002cf80((int)puVar4);
            FUN_80035ff8((int)puVar4);
            FUN_8003709c((int)puVar4,3);
            puVar4[3] = puVar4[3] | 0x4000;
          }
          goto LAB_801f97c8;
        }
      }
      iVar6 = 0;
      do {
        uVar7 = FUN_80020078(iVar6 + 0x2aa);
        uVar10 = uVar10 + uVar7 & 0xff;
        iVar6 = iVar6 + 1;
      } while (iVar6 < 6);
      if (uVar10 < 6) {
        uVar10 = FUN_800803dc((float *)(iVar12 + 0x288));
        if (uVar10 == 0) {
          cVar8 = *(char *)(iVar12 + 0x296);
          if ((((cVar8 == '\x03') || (cVar8 == '\x01')) || (cVar8 == '\x05')) &&
             ((*(ushort *)(iVar12 + 0x294) & 0x80) == 0)) {
            if (cVar8 == '\x05') {
              if (FLOAT_803e6c6c + *(float *)(iVar12 + 0x26c) < FLOAT_803e6c68) {
                *(undefined *)(iVar12 + 0x296) = 3;
                *(undefined2 *)(iVar12 + 0x288) = 0x14;
              }
            }
            else if (FLOAT_803e6c68 < *(float *)(iVar12 + 0x26c)) {
              *(ushort *)(iVar12 + 0x290) = *(short *)(iVar12 + 0x290) - (ushort)DAT_803dc070;
              uVar10 = FUN_8008038c(0x32);
              if (uVar10 != 0) {
                FUN_8000bb38((uint)puVar4,0x74);
              }
              if (*(short *)(iVar12 + 0x290) < 1) {
                if ((*(ushort *)(iVar12 + 0x294) & 0x100) == 0) {
                  if (*(int *)(*(int *)(puVar4 + 0x26) + 0x14) == 0) {
                    uVar13 = FUN_80035ff8((int)puVar4);
                    FUN_8002cc9c(uVar13,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                                 (int)puVar4);
                  }
                  else {
                    FUN_8002cf80((int)puVar4);
                    FUN_80035ff8((int)puVar4);
                    FUN_8003709c((int)puVar4,3);
                    puVar4[3] = puVar4[3] | 0x4000;
                  }
                }
                else {
                  *(undefined *)(iVar12 + 0x296) = 6;
                }
                goto LAB_801f97c8;
              }
              if (*(char *)(iVar12 + 0x296) != '\x05') {
                FUN_8000b7dc((int)puVar4,0x10);
                *(undefined *)(iVar12 + 0x296) = 5;
                fVar2 = FLOAT_803e6c70;
                *(float *)(puVar4 + 0x12) = -*(float *)(puVar4 + 0x12) * FLOAT_803e6c70;
                *(float *)(puVar4 + 0x16) = -*(float *)(puVar4 + 0x16) * fVar2;
              }
            }
          }
          if ((((*(ushort *)(iVar12 + 0x294) & 0x200) != 0) && (*(char *)(iVar12 + 0x296) != '\x05')
              ) && ((iVar6 = FUN_8002ba84(), iVar6 != 0 &&
                    ((dVar14 = (double)FUN_800217c8((float *)(puVar4 + 0xc),(float *)(iVar6 + 0x18))
                     , dVar14 < (double)FLOAT_803e6c6c &&
                     (cVar8 = (**(code **)(**(int **)(iVar6 + 0x68) + 0x44))(iVar6), cVar8 != '\0'))
                    )))) {
            *(undefined *)(iVar12 + 0x296) = 5;
            FUN_8000bb38((uint)puVar4,0x74);
          }
          if (*(char *)(iVar12 + 0x296) == '\x05') {
            if ((*(ushort *)(iVar12 + 0x294) & 2) != 0) {
              (**(code **)(*DAT_803dd728 + 0x10))((double)FLOAT_803dc074,puVar4,iVar12);
              (**(code **)(*DAT_803dd728 + 0x14))(puVar4,iVar12);
              (**(code **)(*DAT_803dd728 + 0x18))((double)FLOAT_803dc074,puVar4,iVar12);
            }
            dVar14 = (double)(*(float *)(puVar4 + 0x12) * *(float *)(puVar4 + 0x12) +
                             *(float *)(puVar4 + 0x16) * *(float *)(puVar4 + 0x16));
            if ((double)FLOAT_803e6c48 != dVar14) {
              dVar19 = FUN_80293900(dVar14);
            }
            *(float *)(iVar12 + 0x284) = (float)((double)FLOAT_803e6c74 * dVar19);
            uStack_3c = (uint)DAT_803dc070;
            local_40 = 0x43300000;
            FUN_8002fb40((double)*(float *)(iVar12 + 0x284),
                         (double)(float)((double)CONCAT44(0x43300000,uStack_3c) - DOUBLE_803e6cb8));
            *(float *)(puVar4 + 6) =
                 *(float *)(puVar4 + 0x12) * FLOAT_803dc074 + *(float *)(puVar4 + 6);
            *(float *)(puVar4 + 10) =
                 *(float *)(puVar4 + 0x16) * FLOAT_803dc074 + *(float *)(puVar4 + 10);
            *(ushort *)(iVar12 + 0x290) = *(short *)(iVar12 + 0x290) - (ushort)DAT_803dc070;
            if ((*(ushort *)(iVar12 + 0x294) & 4) == 0) {
              *(undefined4 *)(puVar4 + 8) = *(undefined4 *)(iVar12 + 0x274);
            }
            else {
              local_48 = FLOAT_803e6c54;
              iVar5 = FUN_80065fcc((double)*(float *)(puVar4 + 6),(double)*(float *)(puVar4 + 8),
                                   (double)*(float *)(puVar4 + 10),puVar4,&local_44,0,0);
              iVar6 = 0;
              puVar9 = local_44;
              if (0 < iVar5) {
                do {
                  fVar2 = *(float *)*puVar9 - *(float *)(puVar4 + 8);
                  if (fVar2 < FLOAT_803e6c48) {
                    fVar2 = fVar2 * FLOAT_803e6c78;
                  }
                  if (fVar2 < local_48) {
                    iVar11 = iVar6;
                    local_48 = fVar2;
                  }
                  puVar9 = puVar9 + 1;
                  iVar6 = iVar6 + 1;
                  iVar5 = iVar5 + -1;
                } while (iVar5 != 0);
              }
              if (local_44 == (undefined4 *)0x0) {
                *(undefined4 *)(puVar4 + 8) = *(undefined4 *)(iVar12 + 0x274);
              }
              else {
                *(undefined4 *)(puVar4 + 8) = *(undefined4 *)local_44[iVar11];
                FUN_801f8640(puVar4,local_44[iVar11]);
              }
            }
            uVar1 = *(ushort *)(iVar12 + 0x294);
            if (((uVar1 & 0x80) == 0) && (*(short *)(iVar12 + 0x290) < 1)) {
              if ((uVar1 & 0x100) == 0) {
                *(undefined *)(iVar12 + 0x296) = 0;
                FUN_8000b7dc((int)puVar4,0x18);
                *(undefined4 *)(puVar4 + 6) = *(undefined4 *)(iVar12 + 0x270);
                uStack_3c = (int)*(short *)(iVar12 + 0x28e) ^ 0x80000000;
                local_40 = 0x43300000;
                *(float *)(puVar4 + 8) =
                     *(float *)(iVar12 + 0x274) +
                     (float)((double)CONCAT44(0x43300000,uStack_3c) - DOUBLE_803e6cc0);
                *(undefined4 *)(puVar4 + 10) = *(undefined4 *)(iVar12 + 0x278);
              }
              else {
                *(undefined *)(iVar12 + 0x296) = 6;
              }
            }
            else if (((uVar1 & 0x200) != 0) && (uVar10 = FUN_80022264(0,0x14), uVar10 == 0)) {
              *(undefined *)(iVar12 + 0x296) = 3;
              uVar10 = FUN_80022264(0,0x14);
              FUN_80080404((float *)(iVar12 + 0x288),(short)uVar10 + 0x32);
            }
          }
          else {
            dVar14 = (double)FUN_80021754((float *)(iVar5 + 0x18),(float *)(puVar4 + 0xc));
            if ((dVar14 < (double)*(float *)(iVar12 + 0x268)) ||
               (uVar10 = FUN_80020078(0x1d9), uVar10 != 0)) {
              cVar8 = *(char *)(iVar12 + 0x296);
              if (cVar8 == '\0') {
                *(undefined *)(iVar12 + 0x296) = 1;
                FUN_80080404((float *)(iVar12 + 0x288),2);
                puVar4[2] = 0;
              }
              else if (cVar8 == '\x01') {
                dVar19 = (double)*(float *)(puVar4 + 0x14);
                if ((double)FLOAT_803e6c7c < dVar19) {
                  *(float *)(puVar4 + 0x14) =
                       (float)((double)FLOAT_803e6c80 * (double)FLOAT_803dc074 + dVar19);
                }
                if (*(float *)(puVar4 + 8) < *(float *)(iVar12 + 0x274)) {
                  *(float *)(puVar4 + 8) = *(float *)(iVar12 + 0x274);
                  *(float *)(puVar4 + 0x14) = FLOAT_803e6c48;
                  *(undefined *)(iVar12 + 0x296) = 3;
                  uVar10 = FUN_80022264(0,0x14);
                  FUN_80080404((float *)(iVar12 + 0x288),(short)uVar10 + 0x32);
                  *(float *)(iVar12 + 0x268) = *(float *)(iVar12 + 0x268) * FLOAT_803e6c84;
                  FUN_8003042c((double)FLOAT_803e6c48,dVar19,param_3,param_4,param_5,param_6,param_7
                               ,param_8,puVar4,0,0,in_r6,in_r7,in_r8,in_r9,in_r10);
                }
              }
              else if (cVar8 == '\x03') {
                FUN_8000bb38((uint)puVar4,0x47);
                if ((*(ushort *)(iVar12 + 0x294) & 2) != 0) {
                  (**(code **)(*DAT_803dd728 + 0x10))((double)FLOAT_803dc074,puVar4,iVar12);
                  (**(code **)(*DAT_803dd728 + 0x14))(puVar4,iVar12);
                  (**(code **)(*DAT_803dd728 + 0x18))((double)FLOAT_803dc074,puVar4,iVar12);
                }
                if ((*(ushort *)(iVar12 + 0x294) & 4) == 0) {
                  *(undefined4 *)(puVar4 + 8) = *(undefined4 *)(iVar12 + 0x274);
                }
                else {
                  local_48 = FLOAT_803e6c54;
                  iVar6 = FUN_80065fcc((double)*(float *)(puVar4 + 6),(double)*(float *)(puVar4 + 8)
                                       ,(double)*(float *)(puVar4 + 10),puVar4,&local_44,0,0);
                  in_r6 = 0;
                  puVar9 = local_44;
                  if (0 < iVar6) {
                    do {
                      fVar2 = *(float *)*puVar9 - *(float *)(puVar4 + 8);
                      if (fVar2 < FLOAT_803e6c48) {
                        fVar2 = fVar2 * FLOAT_803e6c78;
                      }
                      if (fVar2 < local_48) {
                        iVar11 = in_r6;
                        local_48 = fVar2;
                      }
                      puVar9 = puVar9 + 1;
                      in_r6 = in_r6 + 1;
                      iVar6 = iVar6 + -1;
                    } while (iVar6 != 0);
                  }
                  if (local_44 == (undefined4 *)0x0) {
                    *(undefined4 *)(puVar4 + 8) = *(undefined4 *)(iVar12 + 0x274);
                  }
                  else {
                    *(undefined4 *)(puVar4 + 8) = *(undefined4 *)local_44[iVar11];
                    FUN_801f8640(puVar4,local_44[iVar11]);
                  }
                }
                dVar17 = (double)(*(float *)(iVar5 + 0x10) - *(float *)(puVar4 + 8));
                dVar18 = (double)(*(float *)(iVar5 + 0x14) - *(float *)(puVar4 + 10));
                dVar16 = (double)FLOAT_803e6c88;
                *(float *)(puVar4 + 0x12) =
                     (float)((double)(*(float *)(iVar5 + 0xc) - *(float *)(puVar4 + 6)) / dVar16) *
                     FLOAT_803dc074;
                *(float *)(puVar4 + 0x14) = (float)(dVar17 / dVar16) * FLOAT_803dc074;
                *(float *)(puVar4 + 0x16) = (float)(dVar18 / dVar16) * FLOAT_803dc074;
                if ((*(ushort *)(iVar12 + 0x294) & 0x20) != 0) {
                  dVar16 = (double)(*(float *)(puVar4 + 0x16) * *(float *)(puVar4 + 0x16));
                  dVar15 = FUN_80293900((double)(float)(dVar16 + (double)(*(float *)(puVar4 + 0x12)
                                                                          * *(float *)(puVar4 + 0x12
                                                                                      ) +
                                                                         *(float *)(puVar4 + 0x14) *
                                                                         *(float *)(puVar4 + 0x14)))
                                       );
                  if ((double)FLOAT_803dcd98 < dVar15) {
                    FUN_800228f0((float *)(puVar4 + 0x12));
                    *(float *)(puVar4 + 0x12) =
                         *(float *)(puVar4 + 0x12) * FLOAT_803dc074 * FLOAT_803dcd98;
                    *(float *)(puVar4 + 0x14) =
                         *(float *)(puVar4 + 0x14) * FLOAT_803dc074 * FLOAT_803dcd98;
                    dVar16 = (double)*(float *)(puVar4 + 0x16);
                    *(float *)(puVar4 + 0x16) =
                         (float)(dVar16 * (double)(FLOAT_803dc074 * FLOAT_803dcd98));
                  }
                }
                if (((puVar4[0x50] == 0) && ((*(ushort *)(iVar12 + 0x294) & 0x400) != 0)) &&
                   (dVar14 < (double)FLOAT_803e6c8c)) {
                  FUN_8003042c((double)FLOAT_803e6c48,dVar16,dVar17,dVar18,param_5,param_6,param_7,
                               param_8,puVar4,2,0,in_r6,in_r7,in_r8,in_r9,in_r10);
                }
                if ((dVar14 < (double)FLOAT_803e6c90) ||
                   ((((*(ushort *)(iVar12 + 0x294) & 0x10) != 0 &&
                     ((*(ushort *)(*(int *)(puVar4 + 0x2a) + 0x60) & 8) != 0)) &&
                    (dVar14 < (double)FLOAT_803e6c94)))) {
                  DAT_803de938 = DAT_803de938 + 1;
                  if (((puVar4[0x50] == 2) &&
                      (dVar14 = (double)*(float *)(puVar4 + 0x4c), (double)FLOAT_803e6c98 < dVar14))
                     && (dVar14 < (double)FLOAT_803e6c9c)) {
                    in_r6 = 1;
                    FUN_800379bc(dVar14,dVar16,dVar17,dVar18,param_5,param_6,param_7,param_8,iVar5,
                                 0x60004,(uint)puVar4,1,in_r7,in_r8,in_r9,in_r10);
                    DAT_803de938 = 0;
                  }
                  uVar10 = FUN_80020078(0x1d9);
                  if (uVar10 == 0) {
                    if ((2 < DAT_803de938) ||
                       (((*(ushort *)(iVar12 + 0x294) & 0x10) != 0 && (2 < DAT_803de938)))) {
                      uVar13 = FUN_8000bb38((uint)puVar4,0x75);
                      if ((*(ushort *)(iVar12 + 0x294) & 0x10) == 0) {
                        in_r6 = 1;
                        FUN_800379bc(uVar13,dVar16,dVar17,dVar18,param_5,param_6,param_7,param_8,
                                     iVar5,0x60004,(uint)puVar4,1,in_r7,in_r8,in_r9,in_r10);
                      }
                      else {
                        *(byte *)(iVar12 + 0x299) = *(byte *)(iVar12 + 0x299) & 0x7f | 0x80;
                      }
                      DAT_803de938 = 0;
                    }
                  }
                  else {
                    DAT_803de938 = 0;
                  }
                  fVar3 = FLOAT_803e6ca4;
                  fVar2 = FLOAT_803e6ca0;
                  if ((*(ushort *)(iVar12 + 0x294) & 0x10) == 0) {
                    *(float *)(puVar4 + 6) =
                         FLOAT_803e6ca0 * -*(float *)(puVar4 + 0x12) + *(float *)(puVar4 + 6);
                    *(float *)(puVar4 + 10) =
                         fVar2 * -*(float *)(puVar4 + 0x16) + *(float *)(puVar4 + 10);
                  }
                  else {
                    *(float *)(puVar4 + 6) =
                         FLOAT_803e6ca4 * -*(float *)(puVar4 + 0x12) + *(float *)(puVar4 + 6);
                    *(float *)(puVar4 + 10) =
                         fVar3 * -*(float *)(puVar4 + 0x16) + *(float *)(puVar4 + 10);
                  }
                  uVar10 = FUN_80022264(0,0x14);
                  FUN_80080404((float *)(iVar12 + 0x288),(short)uVar10 + 100);
                }
                iVar11 = FUN_80021884();
                *puVar4 = (short)iVar11 + 0x7fff;
                dVar14 = (double)(*(float *)(puVar4 + 0x12) * *(float *)(puVar4 + 0x12) +
                                 *(float *)(puVar4 + 0x16) * *(float *)(puVar4 + 0x16));
                if ((double)FLOAT_803e6c48 != dVar14) {
                  dVar19 = FUN_80293900(dVar14);
                }
                uVar1 = puVar4[0x50];
                if (uVar1 == 1) {
                  *(float *)(iVar12 + 0x284) = FLOAT_803e6c64;
                }
                else if ((short)uVar1 < 1) {
                  if (-1 < (short)uVar1) {
                    *(float *)(iVar12 + 0x284) = (float)((double)FLOAT_803e6ca8 * dVar19);
                  }
                }
                else if ((short)uVar1 < 3) {
                  *(float *)(iVar12 + 0x284) = FLOAT_803e6cac;
                }
                uStack_3c = (uint)DAT_803dc070;
                local_40 = 0x43300000;
                dVar19 = (double)(float)((double)CONCAT44(0x43300000,uStack_3c) - DOUBLE_803e6cb8);
                iVar11 = FUN_8002fb40((double)*(float *)(iVar12 + 0x284),dVar19);
                if ((iVar11 != 0) && (puVar4[0x50] != 0)) {
                  FUN_8003042c((double)FLOAT_803e6c48,dVar19,dVar17,dVar18,param_5,param_6,param_7,
                               param_8,puVar4,0,0,in_r6,in_r7,in_r8,in_r9,in_r10);
                }
                *(float *)(puVar4 + 6) =
                     *(float *)(puVar4 + 0x12) * FLOAT_803dc074 + *(float *)(puVar4 + 6);
                *(float *)(puVar4 + 10) =
                     *(float *)(puVar4 + 0x16) * FLOAT_803dc074 + *(float *)(puVar4 + 10);
              }
            }
            else if (*(char *)(iVar12 + 0x296) == '\x01') {
              dVar19 = (double)*(float *)(puVar4 + 0x14);
              if ((double)FLOAT_803e6c78 < dVar19) {
                *(float *)(puVar4 + 0x14) =
                     (float)((double)FLOAT_803e6cb0 * (double)FLOAT_803dc074 + dVar19);
              }
              if (*(float *)(puVar4 + 8) < *(float *)(iVar12 + 0x274)) {
                *(float *)(puVar4 + 8) = *(float *)(iVar12 + 0x274);
                *(float *)(puVar4 + 0x14) = FLOAT_803e6c48;
                *(undefined *)(iVar12 + 0x296) = 3;
                uVar10 = FUN_80022264(0,0x14);
                FUN_80080404((float *)(iVar12 + 0x288),(short)uVar10 + 0x32);
                *(float *)(iVar12 + 0x268) = *(float *)(iVar12 + 0x268) * FLOAT_803e6c84;
                FUN_8003042c((double)FLOAT_803e6c48,dVar19,param_3,param_4,param_5,param_6,param_7,
                             param_8,puVar4,0,0,in_r6,in_r7,in_r8,in_r9,in_r10);
              }
              *(float *)(puVar4 + 8) =
                   *(float *)(puVar4 + 0x14) * FLOAT_803dc074 + *(float *)(puVar4 + 8);
            }
            if (*(char *)(iVar12 + 0x296) == '\0') {
              *(float *)(puVar4 + 8) =
                   *(float *)(puVar4 + 0x14) * FLOAT_803dc074 + *(float *)(puVar4 + 8);
            }
            uVar10 = FUN_8008038c(0x32);
            if (uVar10 != 0) {
              FUN_8000bb38((uint)puVar4,0x76);
            }
          }
        }
        else {
          FUN_80080434((float *)(iVar12 + 0x288));
        }
      }
      else if (*(int *)(*(int *)(puVar4 + 0x26) + 0x14) == 0) {
        uVar13 = FUN_80035ff8((int)puVar4);
        FUN_8002cc9c(uVar13,param_2,param_3,param_4,param_5,param_6,param_7,param_8,(int)puVar4);
      }
      else {
        FUN_8002cf80((int)puVar4);
        FUN_80035ff8((int)puVar4);
        FUN_8003709c((int)puVar4,3);
        puVar4[3] = puVar4[3] | 0x4000;
      }
    }
  }
LAB_801f97c8:
  FUN_80286888();
  return;
}

