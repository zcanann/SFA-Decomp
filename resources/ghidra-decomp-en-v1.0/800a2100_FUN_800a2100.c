// Function: FUN_800a2100
// Entry: 800a2100
// Size: 3420 bytes

void FUN_800a2100(void)

{
  float fVar1;
  float fVar2;
  float fVar3;
  ushort uVar4;
  bool bVar5;
  bool bVar6;
  double dVar7;
  short sVar11;
  uint *puVar8;
  char cVar12;
  int *piVar9;
  int iVar10;
  int iVar13;
  uint uVar14;
  int iVar15;
  int **ppiVar16;
  char cVar17;
  char cVar18;
  int iVar19;
  int *piVar20;
  int iVar21;
  int iVar22;
  undefined auStack136 [4];
  undefined auStack132 [4];
  undefined2 local_80;
  undefined2 local_7e;
  undefined2 local_7c;
  float local_78;
  float local_74;
  float local_70;
  float local_6c;
  undefined auStack104 [12];
  float local_5c;
  float local_58;
  float local_54;
  double local_50;
  double local_48;
  double local_40;
  
  FUN_802860bc();
  iVar22 = 0;
  DAT_803dc7b0 = 2;
  sVar11 = FUN_80008b4c(0xffffffff);
  if (sVar11 != 1) {
    FLOAT_803dd284 = FLOAT_803db414;
    iVar15 = 0;
    ppiVar16 = (int **)&DAT_8039c1f8;
    do {
      bVar6 = true;
      while (bVar6) {
        bVar6 = false;
        piVar20 = *ppiVar16;
        if ((piVar20 != (int *)0x0) && (*(short *)(piVar20 + 0x43) != -1)) {
          iVar19 = 0;
          *(undefined *)((int)piVar20 + 0x13e) = 0;
          if ((*(short *)((int)piVar20 + 0xfe) < 0) || (*(short *)(piVar20 + 0x3f) == -1)) {
            *(short *)(piVar20 + 0x3f) = *(short *)(piVar20 + 0x3f) + 1;
            if (6 < *(short *)(piVar20 + 0x3f)) {
              FUN_800a1040((int)*(short *)(piVar20 + 0x43),0);
              break;
            }
            *(undefined2 *)((int)piVar20 + 0xfe) =
                 *(undefined2 *)((int)piVar20 + *(short *)(piVar20 + 0x3f) * 2 + 0xee);
            iVar19 = 1;
            FUN_800a0478(piVar20,0);
          }
          else if (*(byte *)(piVar20 + 0x4f) != 0) {
            *(ushort *)(piVar20 + 0x3f) = (ushort)*(byte *)(piVar20 + 0x4f);
            *(undefined *)(piVar20 + 0x4f) = 0;
            if (6 < *(short *)(piVar20 + 0x3f)) {
              FUN_800a1040((int)*(short *)(piVar20 + 0x43),0);
              break;
            }
            *(undefined2 *)((int)piVar20 + 0xfe) =
                 *(undefined2 *)((int)piVar20 + *(short *)(piVar20 + 0x3f) * 2 + 0xee);
            iVar19 = 1;
            FUN_800a0478(piVar20,0);
          }
          cVar17 = '\0';
          cVar18 = '\0';
          FUN_800a0fd0(piVar20,piVar20[0x27] + iVar22 * 0x18,iVar19);
          bVar5 = false;
          iVar21 = 0;
          for (iVar22 = 0; iVar22 < *(char *)((int)piVar20 + 0x139); iVar22 = iVar22 + 1) {
            uVar4 = *(ushort *)(piVar20 + 0x3f);
            iVar13 = piVar20[0x27];
            puVar8 = (uint *)(iVar13 + iVar21);
            if (uVar4 == *(byte *)((int)puVar8 + 0x16)) {
              uVar14 = *puVar8;
              if ((((uVar14 & 0x1000) != 0) && (FLOAT_803df430 < (float)puVar8[1])) &&
                 (0 < (short)uVar4)) {
                *(undefined2 *)(piVar20 + 0x3f) = *(undefined2 *)(iVar13 + iVar22 * 0x18 + 0x14);
                iVar19 = iVar22 * 0x18 + 4;
                *(float *)(piVar20[0x27] + iVar19) =
                     *(float *)(piVar20[0x27] + iVar19) - FLOAT_803df434;
                *(undefined2 *)((int)piVar20 + 0xfe) = 0xffff;
                break;
              }
              if ((uVar14 & 0x2000) != 0) {
                if (*(char *)((int)piVar20 + 0x13a) != '\0') {
                  *(undefined *)((int)piVar20 + 0x13a) = 0;
                  *(undefined4 *)(piVar20[0x27] + iVar22 * 0x18) = 0;
                  *(undefined4 *)(piVar20[0x27] + iVar22 * 0x18) = 0x20;
                  *(undefined2 *)((int)piVar20 + 0xfe) = 0xffff;
                  bVar6 = true;
                  bVar5 = false;
                  break;
                }
                if (0 < (short)uVar4) {
                  bVar5 = true;
                  *(undefined2 *)(piVar20 + 0x3f) = *(undefined2 *)(iVar13 + iVar22 * 0x18 + 0x14);
                  *(undefined2 *)((int)piVar20 + 0xfe) = 0xffff;
                  bVar6 = true;
                  break;
                }
              }
              if ((uVar14 & 0x10000000) != 0) {
                local_5c = (float)piVar20[0x18];
                local_58 = (float)piVar20[0x19];
                local_54 = (float)piVar20[0x1a];
                local_74 = FLOAT_803df430;
                local_70 = FLOAT_803df430;
                local_6c = FLOAT_803df430;
                local_78 = FLOAT_803df434;
                if ((piVar20[0x29] & 1U) == 0) {
                  local_80 = *(undefined2 *)piVar20[1];
                }
                else {
                  local_80 = *(undefined2 *)(piVar20 + 3);
                }
                local_7e = 0;
                local_7c = 0;
                FUN_80021ac8(&local_80,&local_5c);
                if ((*piVar20 == 0) && (cVar12 = FUN_8002e04c(), cVar12 != '\0')) {
                  if ((piVar20[0x29] & 1U) == 0) {
                    iVar13 = piVar20[1];
                    fVar1 = *(float *)(iVar13 + 0x18);
                    fVar2 = *(float *)(iVar13 + 0x1c);
                    fVar3 = *(float *)(iVar13 + 0x20);
                  }
                  else {
                    fVar1 = (float)piVar20[6];
                    fVar2 = (float)piVar20[7];
                    fVar3 = (float)piVar20[8];
                  }
                  local_54 = fVar3 + local_54;
                  local_58 = fVar2 + local_58;
                  local_5c = fVar1 + local_5c;
                  iVar13 = FUN_8002bdf4(0x20,0x66);
                  *(float *)(iVar13 + 8) = local_5c;
                  *(float *)(iVar13 + 0xc) = local_58;
                  *(float *)(iVar13 + 0x10) = local_54;
                  iVar13 = FUN_8002df90(iVar13,5,0xffffffff,0xffffffff,0);
                  *piVar20 = iVar13;
                  *(undefined4 *)(*piVar20 + 0xf8) = 1;
                }
                else if (*piVar20 != 0) {
                  if ((piVar20[0x29] & 1U) == 0) {
                    iVar13 = piVar20[1];
                    fVar1 = *(float *)(iVar13 + 0x18);
                    fVar2 = *(float *)(iVar13 + 0x1c);
                    fVar3 = *(float *)(iVar13 + 0x20);
                  }
                  else {
                    fVar1 = (float)piVar20[6];
                    fVar2 = (float)piVar20[7];
                    fVar3 = (float)piVar20[8];
                  }
                  local_54 = fVar3 + local_54;
                  local_58 = fVar2 + local_58;
                  local_5c = fVar1 + local_5c;
                  *(float *)(*piVar20 + 0x18) = local_5c;
                  *(float *)(*piVar20 + 0x1c) = local_58;
                  *(float *)(*piVar20 + 0x20) = local_54;
                }
                if (((*piVar20 != 0) &&
                    (iVar13 = *(int *)(*(int *)(*piVar20 + 0x54) + 0x50), iVar13 != 0)) &&
                   (iVar10 = (int)*(float *)(piVar20[0x27] + iVar21 + 4),
                   local_50 = (double)(longlong)iVar10, *(short *)(iVar13 + 0x44) == iVar10)) {
                  FUN_8002cbc4();
                  *piVar20 = 0;
                  iVar19 = iVar22 * 0x18;
                  *(uint *)(piVar20[0x27] + iVar19) = *(uint *)(piVar20[0x27] + iVar19) ^ 0x10000000
                  ;
                  fVar1 = *(float *)(piVar20[0x27] + iVar19 + 0xc);
                  if ((FLOAT_803df430 <= fVar1) && (piVar20[1] != 0)) {
                    iVar21 = (int)fVar1;
                    local_50 = (double)(longlong)iVar21;
                    (**(code **)(*DAT_803dca88 + 8))
                              (piVar20[1],iVar21,auStack104,0x200001,0xffffffff,0);
                  }
                  iVar19 = (int)*(float *)(piVar20[0x27] + iVar19 + 8);
                  local_50 = (double)(longlong)iVar19;
                  *(char *)(piVar20 + 0x4f) = (char)iVar19;
                  break;
                }
              }
              FUN_8002e0fc(auStack136,auStack132);
              if ((*(uint *)(piVar20[0x27] + iVar21) & 2) != 0) {
                FUN_800a0c78(piVar20,(uint *)(piVar20[0x27] + iVar21),iVar19,cVar17);
                cVar17 = cVar17 + '\x01';
              }
              if ((*(uint *)(piVar20[0x27] + iVar21) & 4) != 0) {
                FUN_800a0ab4(piVar20,(uint *)(piVar20[0x27] + iVar21),iVar19,cVar18);
                cVar18 = cVar18 + '\x01';
              }
              if ((*(uint *)(piVar20[0x27] + iVar21) & 8) != 0) {
                FUN_800a0524(piVar20,(uint *)(piVar20[0x27] + iVar21),iVar19,0);
              }
              puVar8 = (uint *)(piVar20[0x27] + iVar21);
              if ((*puVar8 & 0x100) != 0) {
                local_50 = (double)(longlong)(int)((float)puVar8[1] * FLOAT_803dd284);
                *(short *)((int)piVar20 + 0x106) =
                     *(short *)((int)piVar20 + 0x106) +
                     (short)(int)((float)puVar8[1] * FLOAT_803dd284);
                local_48 = (double)(longlong)(int)((float)puVar8[2] * FLOAT_803dd284);
                *(short *)(piVar20 + 0x42) =
                     *(short *)(piVar20 + 0x42) + (short)(int)((float)puVar8[2] * FLOAT_803dd284);
                local_40 = (double)(longlong)(int)((float)puVar8[3] * FLOAT_803dd284);
                *(short *)((int)piVar20 + 0x10a) =
                     *(short *)((int)piVar20 + 0x10a) +
                     (short)(int)((float)puVar8[3] * FLOAT_803dd284);
              }
              if ((*(uint *)(piVar20[0x27] + iVar21) & 0x80) != 0) {
                FUN_800a09c4(piVar20,(uint *)(piVar20[0x27] + iVar21),iVar19,0);
              }
              if ((*(uint *)(piVar20[0x27] + iVar21) & 0x8000000) != 0) {
                uVar14 = FUN_800221a0(0,0xffff);
                local_40 = (double)CONCAT44(0x43300000,uVar14 ^ 0x80000000);
                *(float *)(piVar20[0x27] + iVar21 + 0xc) = (float)(local_40 - DOUBLE_803df448);
                FUN_800a09c4(piVar20,piVar20[0x27] + iVar21,iVar19,0);
              }
              if ((*(uint *)(piVar20[0x27] + iVar21) & 0x4000) != 0) {
                FUN_800a02dc(piVar20,(uint *)(piVar20[0x27] + iVar21),iVar19,0);
              }
              if (((*(uint *)(piVar20[0x27] + iVar21) & 0x10000) != 0) && (iVar19 != 0)) {
                uVar14 = (uint)*(short *)((uint *)(piVar20[0x27] + iVar21) + 5);
                if (uVar14 == 0xffffffff) {
                  FUN_8000b7bc(piVar20[1],0x40);
                }
                else {
                  FUN_8000bb18(piVar20[1],uVar14 & 0xffff);
                }
              }
              dVar7 = DOUBLE_803df440;
              puVar8 = (uint *)(piVar20[0x27] + iVar21);
              if ((*puVar8 & 0x100000) != 0) {
                if (iVar19 == 1) {
                  if ((int)*(short *)((int)piVar20 + 0xfe) == 0) {
                    local_40 = (double)CONCAT44(0x43300000,(uint)*(byte *)(piVar20[1] + 0x36));
                    piVar20[0x2f] = (int)((float)puVar8[1] - (float)(local_40 - DOUBLE_803df440));
                    piVar20[0x30] = (int)FLOAT_803df430;
                  }
                  else {
                    local_40 = (double)CONCAT44(0x43300000,(uint)*(byte *)(piVar20[1] + 0x36));
                    local_48 = (double)CONCAT44(0x43300000,
                                                (int)*(short *)((int)piVar20 + 0xfe) ^ 0x80000000);
                    piVar20[0x2f] =
                         (int)(((float)puVar8[1] - (float)(local_40 - DOUBLE_803df440)) /
                              (float)(local_48 - DOUBLE_803df448));
                    local_50 = (double)CONCAT44(0x43300000,(uint)*(byte *)(piVar20[1] + 0x36));
                    piVar20[0x30] = (int)(float)(local_50 - dVar7);
                  }
                }
                piVar20[0x30] = (int)((float)piVar20[0x30] + (float)piVar20[0x2f]);
                if ((float)piVar20[0x30] <= FLOAT_803df43c) {
                  if ((float)piVar20[0x30] < FLOAT_803df430) {
                    piVar20[0x30] = (int)FLOAT_803df430;
                  }
                }
                else {
                  piVar20[0x30] = (int)FLOAT_803df43c;
                }
                local_40 = (double)(longlong)(int)(float)piVar20[0x30];
                *(char *)(piVar20[1] + 0x36) = (char)(int)(float)piVar20[0x30];
              }
              if ((*(uint *)(piVar20[0x27] + iVar21) & 0x400000) != 0) {
                FUN_800a081c(piVar20,(uint *)(piVar20[0x27] + iVar21),iVar19,0);
              }
              puVar8 = (uint *)(piVar20[0x27] + iVar21);
              if ((*puVar8 & 0x80000000) != 0) {
                piVar20[9] = (int)((float)puVar8[1] * FLOAT_803dd284 + (float)piVar20[9]);
                piVar20[10] = (int)((float)puVar8[2] * FLOAT_803dd284 + (float)piVar20[10]);
                piVar20[0xb] = (int)((float)puVar8[3] * FLOAT_803dd284 + (float)piVar20[0xb]);
              }
              puVar8 = (uint *)(piVar20[0x27] + iVar21);
              if ((*puVar8 & 0x800000) != 0) {
                if (((*puVar8 & 0x1000000) == 0) || (FLOAT_803df430 != (float)puVar8[2])) {
                  if (FLOAT_803df430 == (float)puVar8[2]) {
                    iVar13 = 0;
                    while( true ) {
                      iVar10 = iVar21 + piVar20[0x27];
                      local_40 = (double)(longlong)(int)*(float *)(iVar10 + 4);
                      if ((int)*(float *)(iVar10 + 4) <= iVar13) break;
                      if ((piVar20[0x29] & 1U) == 0) {
                        (**(code **)(*DAT_803dca88 + 8))
                                  (piVar20[1],(int)*(short *)(iVar10 + 0x14),0,0x10002,0xffffffff,0)
                        ;
                      }
                      else {
                        (**(code **)(*DAT_803dca88 + 8))
                                  (piVar20[1],(int)*(short *)(iVar10 + 0x14),piVar20 + 3,0x10002,
                                   0xffffffff,0);
                      }
                      iVar13 = iVar13 + 1;
                    }
                  }
                  else if (FLOAT_803df434 == (float)puVar8[2]) {
                    if ((piVar20[0x29] & 1U) == 0) {
                      iVar13 = piVar20[1];
                      local_5c = *(float *)(iVar13 + 0x18) + (float)piVar20[0x18];
                      local_58 = *(float *)(iVar13 + 0x1c) + (float)piVar20[0x19];
                      local_54 = *(float *)(iVar13 + 0x20) + (float)piVar20[0x1a];
                      if (iVar13 != 0) {
                        (**(code **)(*DAT_803dca88 + 8))
                                  (iVar13,(int)*(short *)(piVar20[0x27] + iVar21 + 0x14),auStack104,
                                   0x10001,0xffffffff,0);
                      }
                    }
                    else {
                      local_5c = (float)piVar20[0x18];
                      local_58 = (float)piVar20[0x19];
                      local_54 = (float)piVar20[0x1a];
                      if (piVar20[1] != 0) {
                        (**(code **)(*DAT_803dca88 + 8))
                                  (piVar20[1],(int)*(short *)(piVar20[0x27] + iVar21 + 0x14),
                                   auStack104,0x10001,0xffffffff,0);
                      }
                    }
                  }
                }
                else {
                  iVar13 = 0;
                  while( true ) {
                    iVar10 = (int)*(float *)(iVar21 + piVar20[0x27] + 4);
                    local_40 = (double)(longlong)iVar10;
                    if (iVar10 <= iVar13) break;
                    iVar10 = (int)*(float *)(iVar21 + piVar20[0x27] + 0xc);
                    local_40 = (double)(longlong)iVar10;
                    iVar10 = FUN_800221a0(0,iVar10);
                    if (iVar10 == 0) {
                      if ((piVar20[0x29] & 1U) == 0) {
                        (**(code **)(*DAT_803dca88 + 8))
                                  (piVar20[1],(int)*(short *)(iVar21 + piVar20[0x27] + 0x14),0,
                                   0x10001,0xffffffff,0);
                      }
                      else {
                        (**(code **)(*DAT_803dca88 + 8))
                                  (piVar20[1],(int)*(short *)(iVar21 + piVar20[0x27] + 0x14),0,
                                   0x10001,0xffffffff,0);
                      }
                    }
                    iVar13 = iVar13 + 1;
                  }
                }
              }
              if ((*(uint *)(piVar20[0x27] + iVar21) & 0x4000000) != 0) {
                piVar9 = (int *)FUN_80013ec8(*(short *)((uint *)(piVar20[0x27] + iVar21) + 5) + 0x58
                                             ,1);
                if ((*(uint *)(piVar20[0x27] + iVar21) & 0x1000000) == 0) {
                  for (iVar13 = 0; iVar10 = (int)*(float *)(iVar21 + piVar20[0x27] + 4),
                      local_40 = (double)(longlong)iVar10, iVar13 < iVar10; iVar13 = iVar13 + 1) {
                    if ((piVar20[0x29] & 1U) == 0) {
                      (**(code **)(*piVar9 + 4))(piVar20[1],0,0,1,0xffffffff,0);
                    }
                    else {
                      (**(code **)(*piVar9 + 4))(0,0,piVar20 + 3,1,0xffffffff,0);
                    }
                  }
                }
                else {
                  for (iVar13 = 0; iVar10 = (int)*(float *)(iVar21 + piVar20[0x27] + 4),
                      local_40 = (double)(longlong)iVar10, iVar13 < iVar10; iVar13 = iVar13 + 1) {
                    iVar10 = FUN_800221a0(0,5);
                    if (iVar10 == 0) {
                      if ((piVar20[0x29] & 1U) == 0) {
                        (**(code **)(*piVar9 + 4))(piVar20[1],0,0,1,0xffffffff,0);
                      }
                      else {
                        (**(code **)(*piVar9 + 4))(0,0,piVar20 + 3,1,0xffffffff,0);
                      }
                    }
                  }
                }
                FUN_80013e2c(piVar9);
              }
            }
            iVar21 = iVar21 + 0x18;
          }
          if (!bVar5) {
            *(ushort *)((int)piVar20 + 0xfe) =
                 *(short *)((int)piVar20 + 0xfe) - (ushort)DAT_803db410;
          }
        }
      }
      DAT_803dc7b0 = 0;
      ppiVar16 = ppiVar16 + 1;
      iVar15 = iVar15 + 1;
    } while (iVar15 < 0x32);
  }
  FUN_80286108();
  return;
}

