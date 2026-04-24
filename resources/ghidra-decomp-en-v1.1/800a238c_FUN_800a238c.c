// Function: FUN_800a238c
// Entry: 800a238c
// Size: 3420 bytes

void FUN_800a238c(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)

{
  int iVar1;
  float fVar2;
  float fVar3;
  ushort uVar4;
  bool bVar5;
  bool bVar6;
  int iVar7;
  uint *puVar8;
  undefined2 *puVar9;
  int *piVar10;
  int iVar11;
  int iVar12;
  uint uVar13;
  undefined4 in_r8;
  int in_r9;
  undefined4 in_r10;
  undefined4 *puVar14;
  uint uVar15;
  uint uVar16;
  int iVar17;
  int *piVar18;
  int iVar19;
  int iVar20;
  double dVar21;
  double dVar22;
  double extraout_f1;
  double extraout_f1_00;
  undefined4 uStack_88;
  undefined4 uStack_84;
  ushort local_80 [4];
  float local_78;
  float local_74;
  float local_70;
  float local_6c;
  undefined auStack_68 [12];
  float local_5c;
  float local_58;
  float local_54;
  undefined8 local_50;
  undefined8 local_48;
  undefined8 local_40;
  
  dVar21 = (double)FUN_80286820();
  DAT_803dd430 = 2;
  iVar7 = FUN_80008b4c(-1);
  if ((short)iVar7 != 1) {
    FLOAT_803ddf04 = FLOAT_803dc074;
    iVar7 = 0;
    puVar14 = &DAT_8039ce58;
    do {
      bVar6 = true;
      while (bVar6) {
        bVar6 = false;
        piVar18 = (int *)*puVar14;
        if ((piVar18 != (int *)0x0) && (*(short *)(piVar18 + 0x43) != -1)) {
          iVar17 = 0;
          *(undefined *)((int)piVar18 + 0x13e) = 0;
          if ((*(short *)((int)piVar18 + 0xfe) < 0) || (*(short *)(piVar18 + 0x3f) == -1)) {
            *(short *)(piVar18 + 0x3f) = *(short *)(piVar18 + 0x3f) + 1;
            if (6 < *(short *)(piVar18 + 0x3f)) {
              dVar21 = (double)FUN_800a12cc(dVar21,param_2,param_3,param_4,param_5,param_6,param_7,
                                            param_8,*(short *)(piVar18 + 0x43),0);
              break;
            }
            *(undefined2 *)((int)piVar18 + 0xfe) =
                 *(undefined2 *)((int)piVar18 + *(short *)(piVar18 + 0x3f) * 2 + 0xee);
            iVar17 = 1;
            FUN_800a0704((int)piVar18);
          }
          else if (*(byte *)(piVar18 + 0x4f) != 0) {
            *(ushort *)(piVar18 + 0x3f) = (ushort)*(byte *)(piVar18 + 0x4f);
            *(undefined *)(piVar18 + 0x4f) = 0;
            if (6 < *(short *)(piVar18 + 0x3f)) {
              dVar21 = (double)FUN_800a12cc(dVar21,param_2,param_3,param_4,param_5,param_6,param_7,
                                            param_8,*(short *)(piVar18 + 0x43),0);
              break;
            }
            *(undefined2 *)((int)piVar18 + 0xfe) =
                 *(undefined2 *)((int)piVar18 + *(short *)(piVar18 + 0x3f) * 2 + 0xee);
            iVar17 = 1;
            FUN_800a0704((int)piVar18);
          }
          uVar15 = 0;
          uVar16 = 0;
          dVar21 = (double)FUN_800a125c((int)piVar18);
          bVar5 = false;
          iVar19 = 0;
          for (iVar20 = 0; iVar20 < *(char *)((int)piVar18 + 0x139); iVar20 = iVar20 + 1) {
            uVar4 = *(ushort *)(piVar18 + 0x3f);
            iVar12 = piVar18[0x27];
            puVar8 = (uint *)(iVar12 + iVar19);
            if (uVar4 == *(byte *)((int)puVar8 + 0x16)) {
              uVar13 = *puVar8;
              if ((((uVar13 & 0x1000) != 0) &&
                  (dVar21 = (double)(float)puVar8[1], (double)FLOAT_803e00b0 < dVar21)) &&
                 (0 < (short)uVar4)) {
                *(undefined2 *)(piVar18 + 0x3f) = *(undefined2 *)(iVar12 + iVar20 * 0x18 + 0x14);
                iVar17 = iVar20 * 0x18 + 4;
                dVar21 = (double)*(float *)(piVar18[0x27] + iVar17);
                *(float *)(piVar18[0x27] + iVar17) = (float)(dVar21 - (double)FLOAT_803e00b4);
                *(undefined2 *)((int)piVar18 + 0xfe) = 0xffff;
                break;
              }
              if ((uVar13 & 0x2000) != 0) {
                if (*(char *)((int)piVar18 + 0x13a) != '\0') {
                  *(undefined *)((int)piVar18 + 0x13a) = 0;
                  *(undefined4 *)(piVar18[0x27] + iVar20 * 0x18) = 0;
                  *(undefined4 *)(piVar18[0x27] + iVar20 * 0x18) = 0x20;
                  *(undefined2 *)((int)piVar18 + 0xfe) = 0xffff;
                  bVar6 = true;
                  bVar5 = false;
                  break;
                }
                if (0 < (short)uVar4) {
                  bVar5 = true;
                  *(undefined2 *)(piVar18 + 0x3f) = *(undefined2 *)(iVar12 + iVar20 * 0x18 + 0x14);
                  *(undefined2 *)((int)piVar18 + 0xfe) = 0xffff;
                  bVar6 = true;
                  break;
                }
              }
              if ((uVar13 & 0x10000000) != 0) {
                local_5c = (float)piVar18[0x18];
                local_58 = (float)piVar18[0x19];
                local_54 = (float)piVar18[0x1a];
                local_74 = FLOAT_803e00b0;
                local_70 = FLOAT_803e00b0;
                local_6c = FLOAT_803e00b0;
                local_78 = FLOAT_803e00b4;
                if ((piVar18[0x29] & 1U) == 0) {
                  local_80[0] = *(ushort *)piVar18[1];
                }
                else {
                  local_80[0] = *(ushort *)(piVar18 + 3);
                }
                local_80[1] = 0;
                local_80[2] = 0;
                dVar21 = (double)FUN_80021b8c(local_80,&local_5c);
                if ((*piVar18 == 0) && (uVar13 = FUN_8002e144(), (uVar13 & 0xff) != 0)) {
                  if ((piVar18[0x29] & 1U) == 0) {
                    iVar12 = piVar18[1];
                    fVar2 = *(float *)(iVar12 + 0x18);
                    fVar3 = *(float *)(iVar12 + 0x1c);
                    dVar22 = (double)*(float *)(iVar12 + 0x20);
                    dVar21 = dVar22 + (double)local_54;
                  }
                  else {
                    fVar2 = (float)piVar18[6];
                    fVar3 = (float)piVar18[7];
                    dVar22 = (double)(float)piVar18[8];
                    dVar21 = dVar22 + (double)local_54;
                  }
                  local_54 = (float)dVar21;
                  local_58 = fVar3 + local_58;
                  local_5c = fVar2 + local_5c;
                  puVar9 = FUN_8002becc(0x20,0x66);
                  *(float *)(puVar9 + 4) = local_5c;
                  *(float *)(puVar9 + 6) = local_58;
                  *(float *)(puVar9 + 8) = local_54;
                  iVar12 = FUN_8002e088(dVar22,param_2,param_3,param_4,param_5,param_6,param_7,
                                        param_8,puVar9,5,0xff,0xffffffff,(uint *)0x0,in_r8,in_r9,
                                        in_r10);
                  *piVar18 = iVar12;
                  *(undefined4 *)(*piVar18 + 0xf8) = 1;
                  dVar21 = extraout_f1;
                }
                else if (*piVar18 != 0) {
                  if ((piVar18[0x29] & 1U) == 0) {
                    iVar12 = piVar18[1];
                    fVar2 = *(float *)(iVar12 + 0x18);
                    fVar3 = *(float *)(iVar12 + 0x1c);
                    dVar21 = (double)*(float *)(iVar12 + 0x20);
                    dVar22 = dVar21 + (double)local_54;
                  }
                  else {
                    fVar2 = (float)piVar18[6];
                    fVar3 = (float)piVar18[7];
                    dVar21 = (double)(float)piVar18[8];
                    dVar22 = dVar21 + (double)local_54;
                  }
                  local_54 = (float)dVar22;
                  local_58 = fVar3 + local_58;
                  local_5c = fVar2 + local_5c;
                  *(float *)(*piVar18 + 0x18) = local_5c;
                  *(float *)(*piVar18 + 0x1c) = local_58;
                  *(float *)(*piVar18 + 0x20) = local_54;
                }
                iVar12 = *piVar18;
                if (((iVar12 != 0) &&
                    (iVar11 = *(int *)(*(int *)(iVar12 + 0x54) + 0x50), iVar11 != 0)) &&
                   (iVar1 = (int)*(float *)(piVar18[0x27] + iVar19 + 4),
                   local_50 = (double)(longlong)iVar1, *(short *)(iVar11 + 0x44) == iVar1)) {
                  FUN_8002cc9c(dVar21,param_2,param_3,param_4,param_5,param_6,param_7,param_8,iVar12
                              );
                  *piVar18 = 0;
                  iVar20 = iVar20 * 0x18;
                  *(uint *)(piVar18[0x27] + iVar20) = *(uint *)(piVar18[0x27] + iVar20) ^ 0x10000000
                  ;
                  fVar2 = *(float *)(piVar18[0x27] + iVar20 + 0xc);
                  dVar21 = (double)fVar2;
                  if (((double)FLOAT_803e00b0 <= dVar21) && (piVar18[1] != 0)) {
                    iVar17 = (int)fVar2;
                    local_50 = (double)(longlong)iVar17;
                    in_r8 = 0;
                    in_r9 = *DAT_803dd708;
                    dVar21 = (double)(**(code **)(in_r9 + 8))
                                               (piVar18[1],iVar17,auStack_68,0x200001,0xffffffff);
                  }
                  iVar17 = (int)*(float *)(piVar18[0x27] + iVar20 + 8);
                  local_50 = (double)(longlong)iVar17;
                  *(char *)(piVar18 + 0x4f) = (char)iVar17;
                  break;
                }
              }
              FUN_8002e1f4(&uStack_88,&uStack_84);
              if ((*(uint *)(piVar18[0x27] + iVar19) & 2) != 0) {
                dVar21 = (double)FUN_800a0f04((int)piVar18,piVar18[0x27] + iVar19,iVar17,
                                              uVar15 & 0xff);
                uVar15 = uVar15 + 1;
              }
              if ((*(uint *)(piVar18[0x27] + iVar19) & 4) != 0) {
                dVar21 = (double)FUN_800a0d40((int)piVar18,piVar18[0x27] + iVar19,iVar17,
                                              uVar16 & 0xff);
                uVar16 = uVar16 + 1;
              }
              if ((*(uint *)(piVar18[0x27] + iVar19) & 8) != 0) {
                dVar21 = (double)FUN_800a07b0((int)piVar18,piVar18[0x27] + iVar19,iVar17);
              }
              puVar8 = (uint *)(piVar18[0x27] + iVar19);
              if ((*puVar8 & 0x100) != 0) {
                local_50 = (double)(longlong)(int)((float)puVar8[1] * FLOAT_803ddf04);
                *(short *)((int)piVar18 + 0x106) =
                     *(short *)((int)piVar18 + 0x106) +
                     (short)(int)((float)puVar8[1] * FLOAT_803ddf04);
                local_48 = (double)(longlong)(int)((float)puVar8[2] * FLOAT_803ddf04);
                *(short *)(piVar18 + 0x42) =
                     *(short *)(piVar18 + 0x42) + (short)(int)((float)puVar8[2] * FLOAT_803ddf04);
                dVar21 = (double)(float)puVar8[3];
                local_40 = (double)(longlong)(int)(dVar21 * (double)FLOAT_803ddf04);
                *(short *)((int)piVar18 + 0x10a) =
                     *(short *)((int)piVar18 + 0x10a) +
                     (short)(int)(dVar21 * (double)FLOAT_803ddf04);
              }
              if ((*(uint *)(piVar18[0x27] + iVar19) & 0x80) != 0) {
                dVar21 = (double)FUN_800a0c50((int)piVar18,piVar18[0x27] + iVar19,iVar17);
              }
              if ((*(uint *)(piVar18[0x27] + iVar19) & 0x8000000) != 0) {
                uVar13 = FUN_80022264(0,0xffff);
                local_40 = (double)CONCAT44(0x43300000,uVar13 ^ 0x80000000);
                *(float *)(piVar18[0x27] + iVar19 + 0xc) = (float)(local_40 - DOUBLE_803e00c8);
                dVar21 = (double)FUN_800a0c50((int)piVar18,piVar18[0x27] + iVar19,iVar17);
              }
              if ((*(uint *)(piVar18[0x27] + iVar19) & 0x4000) != 0) {
                dVar21 = (double)FUN_800a0568((int)piVar18,piVar18[0x27] + iVar19);
              }
              if (((*(uint *)(piVar18[0x27] + iVar19) & 0x10000) != 0) && (iVar17 != 0)) {
                uVar4 = *(ushort *)((uint *)(piVar18[0x27] + iVar19) + 5);
                if (uVar4 == 0xffff) {
                  dVar21 = (double)FUN_8000b7dc(piVar18[1],0x40);
                }
                else {
                  dVar21 = (double)FUN_8000bb38(piVar18[1],uVar4);
                }
              }
              dVar22 = DOUBLE_803e00c0;
              puVar8 = (uint *)(piVar18[0x27] + iVar19);
              if ((*puVar8 & 0x100000) != 0) {
                if (iVar17 == 1) {
                  if ((int)*(short *)((int)piVar18 + 0xfe) == 0) {
                    param_2 = (double)(float)puVar8[1];
                    local_40 = (double)CONCAT44(0x43300000,(uint)*(byte *)(piVar18[1] + 0x36));
                    piVar18[0x2f] =
                         (int)(float)(param_2 - (double)(float)(local_40 - DOUBLE_803e00c0));
                    piVar18[0x30] = (int)FLOAT_803e00b0;
                  }
                  else {
                    local_40 = (double)CONCAT44(0x43300000,(uint)*(byte *)(piVar18[1] + 0x36));
                    param_2 = (double)((float)puVar8[1] - (float)(local_40 - DOUBLE_803e00c0));
                    local_48 = (double)CONCAT44(0x43300000,
                                                (int)*(short *)((int)piVar18 + 0xfe) ^ 0x80000000);
                    piVar18[0x2f] =
                         (int)(float)(param_2 / (double)(float)(local_48 - DOUBLE_803e00c8));
                    local_50 = (double)CONCAT44(0x43300000,(uint)*(byte *)(piVar18[1] + 0x36));
                    piVar18[0x30] = (int)(float)(local_50 - dVar22);
                    param_3 = dVar22;
                  }
                }
                piVar18[0x30] = (int)((float)piVar18[0x30] + (float)piVar18[0x2f]);
                dVar21 = (double)(float)piVar18[0x30];
                if (dVar21 <= (double)FLOAT_803e00bc) {
                  if (dVar21 < (double)FLOAT_803e00b0) {
                    piVar18[0x30] = (int)FLOAT_803e00b0;
                  }
                }
                else {
                  piVar18[0x30] = (int)FLOAT_803e00bc;
                }
                local_40 = (double)(longlong)(int)(float)piVar18[0x30];
                *(char *)(piVar18[1] + 0x36) = (char)(int)(float)piVar18[0x30];
              }
              if ((*(uint *)(piVar18[0x27] + iVar19) & 0x400000) != 0) {
                dVar21 = (double)FUN_800a0aa8((int)piVar18,piVar18[0x27] + iVar19,iVar17);
              }
              puVar8 = (uint *)(piVar18[0x27] + iVar19);
              if ((*puVar8 & 0x80000000) != 0) {
                piVar18[9] = (int)((float)puVar8[1] * FLOAT_803ddf04 + (float)piVar18[9]);
                piVar18[10] = (int)((float)puVar8[2] * FLOAT_803ddf04 + (float)piVar18[10]);
                param_2 = (double)(float)puVar8[3];
                dVar21 = (double)FLOAT_803ddf04;
                piVar18[0xb] = (int)(float)(param_2 * dVar21 + (double)(float)piVar18[0xb]);
              }
              puVar8 = (uint *)(piVar18[0x27] + iVar19);
              if ((*puVar8 & 0x800000) != 0) {
                if (((*puVar8 & 0x1000000) == 0) ||
                   (dVar21 = (double)FLOAT_803e00b0, dVar21 != (double)(float)puVar8[2])) {
                  dVar21 = (double)(float)puVar8[2];
                  if ((double)FLOAT_803e00b0 == dVar21) {
                    iVar12 = 0;
                    while( true ) {
                      iVar11 = iVar19 + piVar18[0x27];
                      local_40 = (double)(longlong)(int)*(float *)(iVar11 + 4);
                      if ((int)*(float *)(iVar11 + 4) <= iVar12) break;
                      if ((piVar18[0x29] & 1U) == 0) {
                        in_r8 = 0;
                        in_r9 = *DAT_803dd708;
                        dVar21 = (double)(**(code **)(in_r9 + 8))
                                                   (piVar18[1],(int)*(short *)(iVar11 + 0x14),0,
                                                    0x10002,0xffffffff);
                      }
                      else {
                        in_r8 = 0;
                        in_r9 = *DAT_803dd708;
                        dVar21 = (double)(**(code **)(in_r9 + 8))
                                                   (piVar18[1],(int)*(short *)(iVar11 + 0x14),
                                                    piVar18 + 3,0x10002,0xffffffff);
                      }
                      iVar12 = iVar12 + 1;
                    }
                  }
                  else if ((double)FLOAT_803e00b4 == dVar21) {
                    if ((piVar18[0x29] & 1U) == 0) {
                      iVar12 = piVar18[1];
                      local_5c = *(float *)(iVar12 + 0x18) + (float)piVar18[0x18];
                      local_58 = *(float *)(iVar12 + 0x1c) + (float)piVar18[0x19];
                      dVar21 = (double)*(float *)(iVar12 + 0x20);
                      local_54 = (float)(dVar21 + (double)(float)piVar18[0x1a]);
                      if (iVar12 != 0) {
                        in_r8 = 0;
                        in_r9 = *DAT_803dd708;
                        dVar21 = (double)(**(code **)(in_r9 + 8))
                                                   (iVar12,(int)*(short *)(piVar18[0x27] +
                                                                          iVar19 + 0x14),auStack_68,
                                                    0x10001,0xffffffff);
                      }
                    }
                    else {
                      local_5c = (float)piVar18[0x18];
                      local_58 = (float)piVar18[0x19];
                      local_54 = (float)piVar18[0x1a];
                      if (piVar18[1] != 0) {
                        in_r8 = 0;
                        in_r9 = *DAT_803dd708;
                        dVar21 = (double)(**(code **)(in_r9 + 8))
                                                   (piVar18[1],
                                                    (int)*(short *)(piVar18[0x27] + iVar19 + 0x14),
                                                    auStack_68,0x10001,0xffffffff);
                      }
                    }
                  }
                }
                else {
                  iVar12 = 0;
                  while( true ) {
                    iVar11 = (int)*(float *)(iVar19 + piVar18[0x27] + 4);
                    local_40 = (double)(longlong)iVar11;
                    if (iVar11 <= iVar12) break;
                    uVar13 = (uint)*(float *)(iVar19 + piVar18[0x27] + 0xc);
                    local_40 = (double)(longlong)(int)uVar13;
                    uVar13 = FUN_80022264(0,uVar13);
                    if (uVar13 == 0) {
                      if ((piVar18[0x29] & 1U) == 0) {
                        in_r8 = 0;
                        in_r9 = *DAT_803dd708;
                        dVar21 = (double)(**(code **)(in_r9 + 8))
                                                   (piVar18[1],
                                                    (int)*(short *)(iVar19 + piVar18[0x27] + 0x14),0
                                                    ,0x10001,0xffffffff);
                      }
                      else {
                        in_r8 = 0;
                        in_r9 = *DAT_803dd708;
                        dVar21 = (double)(**(code **)(in_r9 + 8))
                                                   (piVar18[1],
                                                    (int)*(short *)(iVar19 + piVar18[0x27] + 0x14),0
                                                    ,0x10001,0xffffffff);
                      }
                    }
                    iVar12 = iVar12 + 1;
                  }
                }
              }
              if ((*(uint *)(piVar18[0x27] + iVar19) & 0x4000000) != 0) {
                piVar10 = (int *)FUN_80013ee8((int)*(short *)((uint *)(piVar18[0x27] + iVar19) + 5)
                                              + 0x58U & 0xffff);
                dVar21 = extraout_f1_00;
                if ((*(uint *)(piVar18[0x27] + iVar19) & 0x1000000) == 0) {
                  for (iVar12 = 0; iVar11 = (int)*(float *)(iVar19 + piVar18[0x27] + 4),
                      local_40 = (double)(longlong)iVar11, iVar12 < iVar11; iVar12 = iVar12 + 1) {
                    if ((piVar18[0x29] & 1U) == 0) {
                      in_r8 = 0;
                      in_r9 = *piVar10;
                      dVar21 = (double)(**(code **)(in_r9 + 4))(piVar18[1],0,0,1,0xffffffff);
                    }
                    else {
                      in_r8 = 0;
                      in_r9 = *piVar10;
                      dVar21 = (double)(**(code **)(in_r9 + 4))(0,0,piVar18 + 3,1,0xffffffff);
                    }
                  }
                }
                else {
                  for (iVar12 = 0; iVar11 = (int)*(float *)(iVar19 + piVar18[0x27] + 4),
                      local_40 = (double)(longlong)iVar11, iVar12 < iVar11; iVar12 = iVar12 + 1) {
                    uVar13 = FUN_80022264(0,5);
                    if (uVar13 == 0) {
                      if ((piVar18[0x29] & 1U) == 0) {
                        in_r8 = 0;
                        in_r9 = *piVar10;
                        dVar21 = (double)(**(code **)(in_r9 + 4))(piVar18[1],0,0,1,0xffffffff);
                      }
                      else {
                        in_r8 = 0;
                        in_r9 = *piVar10;
                        dVar21 = (double)(**(code **)(in_r9 + 4))(0,0,piVar18 + 3,1,0xffffffff);
                      }
                    }
                  }
                }
                FUN_80013e4c((undefined *)piVar10);
              }
            }
            iVar19 = iVar19 + 0x18;
          }
          if (!bVar5) {
            *(ushort *)((int)piVar18 + 0xfe) =
                 *(short *)((int)piVar18 + 0xfe) - (ushort)DAT_803dc070;
          }
        }
      }
      DAT_803dd430 = 0;
      puVar14 = puVar14 + 1;
      iVar7 = iVar7 + 1;
    } while (iVar7 < 0x32);
  }
  FUN_8028686c();
  return;
}

