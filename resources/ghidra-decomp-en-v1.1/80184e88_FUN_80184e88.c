// Function: FUN_80184e88
// Entry: 80184e88
// Size: 3476 bytes

/* WARNING: Removing unreachable block (ram,0x80185bfc) */
/* WARNING: Removing unreachable block (ram,0x80184e98) */

void FUN_80184e88(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)

{
  char cVar1;
  float fVar2;
  short sVar3;
  ushort uVar4;
  bool bVar5;
  float fVar6;
  float fVar7;
  float fVar8;
  float fVar9;
  ushort *puVar10;
  int iVar11;
  int iVar12;
  uint uVar13;
  undefined4 *puVar14;
  int iVar15;
  float *in_r7;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  float *pfVar16;
  int iVar17;
  double dVar18;
  undefined8 uVar19;
  double dVar20;
  double dVar21;
  double in_f31;
  double in_ps31_1;
  undefined4 local_170;
  undefined4 local_16c;
  undefined4 local_168;
  float local_164;
  uint local_160;
  undefined4 *local_15c;
  float local_158 [3];
  float local_14c;
  float local_148;
  float local_144;
  float local_140;
  float local_13c;
  float local_138;
  uint auStack_134 [6];
  ushort local_11c [4];
  float local_114;
  float local_110;
  float local_10c;
  float local_108;
  int aiStack_104 [21];
  float afStack_b0 [16];
  float local_70 [4];
  undefined local_60;
  undefined local_5c;
  undefined8 local_40;
  undefined8 local_38;
  float local_8;
  float fStack_4;
  
  local_8 = (float)in_f31;
  fStack_4 = (float)in_ps31_1;
  puVar10 = (ushort *)FUN_8028683c();
  iVar17 = 0;
  local_15c = (undefined4 *)0x0;
  local_140 = DAT_802c2a18;
  local_13c = DAT_802c2a1c;
  local_138 = DAT_802c2a20;
  local_14c = DAT_802c2a24;
  local_148 = DAT_802c2a28;
  local_144 = DAT_802c2a2c;
  bVar5 = false;
  pfVar16 = *(float **)(puVar10 + 0x5c);
  iVar11 = FUN_8002bac4();
  if ((*(byte *)(pfVar16 + 10) & 1) != 0) {
    while (iVar12 = FUN_800375e4((int)puVar10,&local_160,(uint *)0x0,(uint *)0x0), iVar12 != 0) {
      if (local_160 == 0x7000b) {
        local_168 = DAT_803e4688;
        FUN_8029700c(iVar11,(uint)*(byte *)((int)&local_168 + (uint)*(byte *)((int)pfVar16 + 0x27)))
        ;
        *(undefined2 *)(pfVar16 + 4) = 0x50;
        *(undefined2 *)(pfVar16 + 5) = 0;
        *(byte *)(pfVar16 + 10) = *(byte *)(pfVar16 + 10) & 0xfe;
      }
    }
    if ((*(byte *)(pfVar16 + 10) & 1) != 0) goto LAB_80185bfc;
  }
  uVar19 = FUN_8000d904((uint)puVar10,0x406,3);
  fVar2 = FLOAT_803e46b8;
  sVar3 = *(short *)(pfVar16 + 5);
  if (sVar3 == 0) {
    *(ushort *)(pfVar16 + 4) = *(short *)(pfVar16 + 4) - (ushort)DAT_803dc070;
    if (*(short *)(pfVar16 + 4) < 1) {
      *(undefined2 *)(pfVar16 + 4) = 0;
      FUN_8002cc9c(uVar19,param_2,param_3,param_4,param_5,param_6,param_7,param_8,(int)puVar10);
    }
  }
  else {
    cVar1 = *(char *)(pfVar16 + 9);
    if (cVar1 == '\0') {
      if (*(int *)(puVar10 + 0x2a) != 0) {
        FUN_80036018((int)puVar10);
      }
      *(float *)(puVar10 + 6) =
           *(float *)(puVar10 + 0x12) * FLOAT_803dc074 + *(float *)(puVar10 + 6);
      *(float *)(puVar10 + 8) =
           *(float *)(puVar10 + 0x14) * FLOAT_803dc074 + *(float *)(puVar10 + 8);
      *(float *)(puVar10 + 10) =
           *(float *)(puVar10 + 0x16) * FLOAT_803dc074 + *(float *)(puVar10 + 10);
      if (FLOAT_803e46a0 < *(float *)(puVar10 + 0x14)) {
        *(float *)(puVar10 + 0x14) = FLOAT_803e46a4 * FLOAT_803dc074 + *(float *)(puVar10 + 0x14);
      }
      puVar10[2] = puVar10[2] + *(short *)((int)pfVar16 + 0x16) * (ushort)DAT_803dc070;
      iVar17 = FUN_80184918();
      uVar13 = (uint)(iVar17 != 0);
      if (uVar13 == 0) {
        uVar13 = FUN_80064248(puVar10 + 0x40,puVar10 + 6,(float *)0x0,aiStack_104,(int *)puVar10,8,
                              0xffffffff,0,0);
      }
      if (uVar13 != 0) {
        puVar10[2] = 0;
        *(undefined *)(pfVar16 + 9) = 1;
        *(ushort *)(pfVar16 + 6) = *puVar10;
        fVar9 = FLOAT_803e46b4;
        fVar8 = FLOAT_803e46b0;
        fVar7 = FLOAT_803e46ac;
        fVar6 = FLOAT_803e46a8;
        fVar2 = FLOAT_803e4690;
        uVar4 = puVar10[0x23];
        if (uVar4 == 0x3d3) {
          *pfVar16 = FLOAT_803e46a8 * *(float *)(puVar10 + 0x12);
          pfVar16[1] = fVar6 * *(float *)(puVar10 + 0x16);
        }
        else if (uVar4 == 0x3d4) {
          *pfVar16 = FLOAT_803e46ac * *(float *)(puVar10 + 0x12);
          pfVar16[1] = fVar7 * *(float *)(puVar10 + 0x16);
        }
        else if (uVar4 == 0x3d5) {
          *pfVar16 = FLOAT_803e46b0 * *(float *)(puVar10 + 0x12);
          pfVar16[1] = fVar8 * *(float *)(puVar10 + 0x16);
        }
        else if (uVar4 == 0x3d6) {
          *pfVar16 = FLOAT_803e46b4 * *(float *)(puVar10 + 0x12);
          pfVar16[1] = fVar9 * *(float *)(puVar10 + 0x16);
        }
        else if (uVar4 == 0x3df) {
          *pfVar16 = FLOAT_803e4690;
          pfVar16[1] = fVar2;
        }
      }
    }
    else if ((cVar1 == '\x02') && (sVar3 != 0)) {
      local_40 = (double)CONCAT44(0x43300000,(int)*(short *)(pfVar16 + 7) ^ 0x80000000);
      if (pfVar16[2] < (float)(local_40 - DOUBLE_803e46e0)) {
        pfVar16[2] = FLOAT_803e46b8 * FLOAT_803dc074 + pfVar16[2];
        local_140 = *(float *)(puVar10 + 6);
        local_14c = fVar2 * *(float *)(puVar10 + 0x12) * FLOAT_803dc074 + local_140;
        local_13c = *(float *)(puVar10 + 8);
        local_148 = fVar2 * FLOAT_803dc074 + local_13c;
        local_138 = *(float *)(puVar10 + 10);
        local_144 = fVar2 * *(float *)(puVar10 + 0x16) * FLOAT_803dc074 + local_138;
        local_70[0] = FLOAT_803e4690;
        local_60 = 0xff;
        local_5c = 0;
        FUN_80069798(auStack_134,&local_140,&local_14c,local_70,1);
        FUN_8006933c(puVar10,auStack_134,0,'\x01');
        iVar17 = FUN_80067ad4();
        *(float *)(puVar10 + 6) = local_14c;
        *(float *)(puVar10 + 8) = local_148;
        *(float *)(puVar10 + 10) = local_144;
        if (iVar17 != 0) {
          FUN_80184b54(puVar10,0,'\0',afStack_b0);
        }
      }
      iVar17 = FUN_80036974((int)puVar10,(undefined4 *)0x0,(int *)0x0,(uint *)0x0);
      if (iVar17 == 0xe) {
        *(undefined2 *)((int)pfVar16 + 0x1a) = 0xfa;
        FUN_8000bb38((uint)puVar10,0x40);
        *(float *)(puVar10 + 0x12) = *(float *)(iVar11 + 0xc) - *(float *)(puVar10 + 6);
        *(float *)(puVar10 + 0x16) = *(float *)(iVar11 + 0x14) - *(float *)(puVar10 + 10);
        *puVar10 = 0;
        dVar20 = (double)(*(float *)(puVar10 + 0x12) * *(float *)(puVar10 + 0x12) +
                         *(float *)(puVar10 + 0x16) * *(float *)(puVar10 + 0x16));
        if (dVar20 != (double)FLOAT_803e4690) {
          dVar20 = FUN_80293900(dVar20);
        }
        dVar18 = (double)FLOAT_803e4694;
        *(float *)(puVar10 + 0x12) = *(float *)(puVar10 + 0x12) / (float)(dVar18 * dVar20);
        *(float *)(puVar10 + 0x16) = *(float *)(puVar10 + 0x16) / (float)(dVar18 * dVar20);
        puVar10[1] = 0;
        *(float *)(puVar10 + 0x14) = FLOAT_803e46bc;
        local_110 = FLOAT_803e4690;
        local_10c = FLOAT_803e4690;
        local_108 = FLOAT_803e4690;
        local_114 = FLOAT_803e4698;
        local_11c[2] = 0;
        local_11c[1] = 0;
        uVar13 = FUN_80022264(0xffffd8f0,10000);
        local_11c[0] = (ushort)uVar13;
        FUN_80021b8c(local_11c,(float *)(puVar10 + 0x12));
        uVar13 = FUN_80021884();
        iVar17 = (int)(short)*puVar10 - (uVar13 & 0xffff);
        if (0x8000 < iVar17) {
          iVar17 = iVar17 + -0xffff;
        }
        if (iVar17 < -0x8000) {
          iVar17 = iVar17 + 0xffff;
        }
        *puVar10 = (ushort)iVar17;
        *(undefined *)(pfVar16 + 9) = 0;
        pfVar16[2] = FLOAT_803e4690;
        fVar2 = FLOAT_803e468c;
        *(float *)(puVar10 + 6) =
             FLOAT_803e468c * *(float *)(puVar10 + 0x12) * FLOAT_803dc074 + *(float *)(puVar10 + 6);
        *(float *)(puVar10 + 8) =
             fVar2 * *(float *)(puVar10 + 0x14) * FLOAT_803dc074 + *(float *)(puVar10 + 8);
        *(float *)(puVar10 + 10) =
             fVar2 * *(float *)(puVar10 + 0x16) * FLOAT_803dc074 + *(float *)(puVar10 + 10);
      }
    }
    else if ((cVar1 == '\x01') && (sVar3 != 0)) {
      if (*(short *)((int)pfVar16 + 0x1a) == 0) {
        iVar17 = 0;
        dVar20 = (double)FLOAT_803e46c0;
        iVar12 = FUN_80065fcc((double)*(float *)(puVar10 + 6),(double)*(float *)(puVar10 + 8),
                              (double)*(float *)(puVar10 + 10),puVar10,&local_15c,1,0);
        iVar15 = 0;
        dVar21 = (double)FLOAT_803dca30;
        puVar14 = local_15c;
        if (0 < iVar12) {
          do {
            dVar18 = (double)(*(float *)*puVar14 - *(float *)(puVar10 + 8));
            if (dVar18 <= dVar21) {
              if (dVar18 < (double)FLOAT_803e4690) {
                dVar18 = -dVar18;
              }
              if (dVar18 < dVar20) {
                iVar17 = iVar15;
                dVar20 = dVar18;
              }
            }
            puVar14 = puVar14 + 1;
            iVar15 = iVar15 + 1;
            iVar12 = iVar12 + -1;
          } while (iVar12 != 0);
        }
        if (local_15c == (undefined4 *)0x0) {
          *(float *)(puVar10 + 8) = pfVar16[3];
        }
        else {
          *(undefined4 *)(puVar10 + 8) = *(undefined4 *)local_15c[iVar17];
          fVar2 = *(float *)(local_15c[iVar17] + 8);
          if (fVar2 < FLOAT_803e4690) {
            fVar2 = -fVar2;
          }
          if (FLOAT_803dca2c <= fVar2) {
            FUN_80184b54(puVar10,local_15c[iVar17],'\x01',afStack_b0);
          }
          else {
            bVar5 = true;
          }
        }
        if (puVar10[0x23] != 0x3d6) {
          uVar13 = FUN_80022264(0xfffffa4c,0x5b4);
          *puVar10 = *puVar10 + (short)uVar13;
        }
        *(float *)(puVar10 + 0x12) = *pfVar16;
        local_110 = FLOAT_803e4690;
        *(float *)(puVar10 + 0x14) = FLOAT_803e4690;
        *(float *)(puVar10 + 0x16) = pfVar16[1];
        local_10c = local_110;
        local_108 = local_110;
        local_114 = FLOAT_803e4698;
        local_11c[2] = 0;
        local_11c[1] = 0;
        local_11c[0] = *puVar10 - *(short *)(pfVar16 + 6);
        FUN_80021b8c(local_11c,(float *)(puVar10 + 0x12));
        *(ushort *)(pfVar16 + 5) = *(short *)(pfVar16 + 5) - (ushort)DAT_803dc070;
        if (*(short *)(pfVar16 + 5) < 1) {
          iVar12 = FUN_8005a288((double)(*(float *)(puVar10 + 0x54) * *(float *)(puVar10 + 4)),
                                (float *)(puVar10 + 6));
          if (iVar12 == 0) {
            *(undefined2 *)(pfVar16 + 5) = 0;
          }
          else {
            *(undefined2 *)(pfVar16 + 5) = 1;
          }
        }
        if (bVar5) {
          uVar13 = FUN_80021884();
          local_40 = (double)CONCAT44(0x43300000,uVar13 & 0xffff);
          iVar12 = (int)(FLOAT_803dca34 * (float)(local_40 - DOUBLE_803e46e8) + FLOAT_803e46c4);
          local_38 = (double)(longlong)iVar12;
          *puVar10 = (ushort)iVar12;
          dVar21 = (double)FLOAT_803e468c;
          *(float *)(puVar10 + 6) =
               FLOAT_803dc074 * (float)(dVar21 * (double)*(float *)(local_15c[iVar17] + 4)) +
               *(float *)(puVar10 + 6);
          dVar18 = (double)FLOAT_803dc074;
          *(float *)(puVar10 + 10) =
               (float)(dVar18 * (double)(float)(dVar21 * (double)*(float *)(local_15c[iVar17] + 0xc)
                                               ) + (double)*(float *)(puVar10 + 10));
          *(undefined4 *)(puVar10 + 0x12) = *(undefined4 *)(local_15c[iVar17] + 4);
          *(undefined4 *)(puVar10 + 0x16) = *(undefined4 *)(local_15c[iVar17] + 0xc);
        }
        else {
          *(float *)(puVar10 + 6) =
               *(float *)(puVar10 + 0x12) * FLOAT_803dc074 + *(float *)(puVar10 + 6);
          *(float *)(puVar10 + 10) =
               *(float *)(puVar10 + 0x16) * FLOAT_803dc074 + *(float *)(puVar10 + 10);
          dVar20 = FUN_80293900((double)(*(float *)(puVar10 + 0x12) * *(float *)(puVar10 + 0x12) +
                                        *(float *)(puVar10 + 0x16) * *(float *)(puVar10 + 0x16)));
          FUN_8002f6cc(dVar20,(int)puVar10,&local_164);
          dVar18 = (double)FLOAT_803dc074;
          FUN_8002fb40((double)local_164,dVar18);
        }
        in_r9 = 0xffffffff;
        in_r10 = 0;
        iVar17 = FUN_80064248(puVar10 + 0x40,puVar10 + 6,(float *)0x0,aiStack_104,(int *)puVar10,8,
                              0xffffffff,0,0);
        local_70[0] = FLOAT_803e4698;
        local_60 = 0xff;
        local_5c = 10;
        FUN_80069798(auStack_134,(float *)(puVar10 + 0x40),(float *)(puVar10 + 6),local_70,1);
        FUN_8006933c(puVar10,auStack_134,0,'\x01');
        in_r7 = afStack_b0;
        in_r8 = 0;
        uVar13 = FUN_80067ad4();
        if (((iVar17 != 0) ||
            (dVar20 = (double)FUN_800217c8((float *)(puVar10 + 0xc),
                                           (float *)(*(int *)(puVar10 + 0x26) + 8)),
            (double)FLOAT_803e46c8 < dVar20)) || (((uVar13 & 1) != 0 && ((uVar13 & 0x10) == 0)))) {
          FUN_80247eb8((float *)(*(int *)(puVar10 + 0x26) + 8),(float *)(puVar10 + 6),local_158);
          uVar13 = FUN_80021884();
          local_38 = (double)CONCAT44(0x43300000,uVar13 & 0xffff);
          dVar18 = (double)(float)(local_38 - DOUBLE_803e46e8);
          iVar17 = (int)((double)FLOAT_803dca38 * dVar18 + (double)FLOAT_803e46c4);
          local_40 = (double)(longlong)iVar17;
          *puVar10 = (ushort)iVar17;
        }
      }
      else {
        dVar20 = (double)FLOAT_803e46c0;
        dVar18 = (double)*(float *)(puVar10 + 8);
        dVar21 = (double)*(float *)(puVar10 + 10);
        iVar12 = FUN_80065fcc((double)*(float *)(puVar10 + 6),dVar18,dVar21,puVar10,&local_15c,1,0);
        iVar15 = 0;
        puVar14 = local_15c;
        if (0 < iVar12) {
          do {
            dVar21 = (double)*(float *)*puVar14;
            dVar18 = (double)(float)(dVar21 - (double)*(float *)(puVar10 + 8));
            if (dVar18 < (double)FLOAT_803e4690) {
              dVar18 = (double)(float)(dVar18 * (double)FLOAT_803e46cc);
            }
            if (dVar18 < dVar20) {
              iVar17 = iVar15;
              dVar20 = dVar18;
            }
            puVar14 = puVar14 + 1;
            iVar15 = iVar15 + 1;
            iVar12 = iVar12 + -1;
          } while (iVar12 != 0);
        }
        if (local_15c == (undefined4 *)0x0) {
          *(float *)(puVar10 + 8) = pfVar16[3];
        }
        else {
          *(undefined4 *)(puVar10 + 8) = *(undefined4 *)local_15c[iVar17];
          FUN_80184b54(puVar10,local_15c[iVar17],'\x01',afStack_b0);
        }
        *(ushort *)((int)pfVar16 + 0x1a) = *(short *)((int)pfVar16 + 0x1a) - (ushort)DAT_803dc070;
        if (*(short *)((int)pfVar16 + 0x1a) < 1) {
          *(undefined2 *)((int)pfVar16 + 0x1a) = 0;
        }
      }
      if (((*(short *)((int)pfVar16 + 0x1a) != 0) || (puVar10[0x23] != 0x3d6)) &&
         (dVar20 = (double)FUN_80021754((float *)(iVar11 + 0x18),(float *)(puVar10 + 0xc)),
         dVar20 < (double)FLOAT_803e46d0)) {
        dVar20 = (double)(*(float *)(puVar10 + 8) - *(float *)(iVar11 + 0x10));
        if (dVar20 < (double)FLOAT_803e4690) {
          dVar20 = -dVar20;
        }
        if (dVar20 < (double)FLOAT_803e46d4) {
          uVar13 = FUN_80020078(0x910);
          if (uVar13 == 0) {
            *(undefined2 *)(pfVar16 + 0xb) = 0xffff;
            *(undefined2 *)((int)pfVar16 + 0x2e) = 0;
            pfVar16[0xc] = FLOAT_803e4698;
            FUN_800379bc(dVar20,dVar18,dVar21,param_4,param_5,param_6,param_7,param_8,iVar11,0x7000a
                         ,(uint)puVar10,(uint)(pfVar16 + 0xb),in_r7,in_r8,in_r9,in_r10);
            FUN_800201ac(0x910,1);
            *(byte *)(pfVar16 + 10) = *(byte *)(pfVar16 + 10) | 1;
          }
          else {
            local_16c = DAT_803e4688;
            FUN_8029700c(iVar11,(uint)*(byte *)((int)&local_16c +
                                               (uint)*(byte *)((int)pfVar16 + 0x27)));
            *(undefined2 *)(pfVar16 + 4) = 0x50;
            *(undefined2 *)(pfVar16 + 5) = 0;
          }
          if (*(int *)(puVar10 + 0x2a) != 0) {
            FUN_80035ff8((int)puVar10);
          }
          FUN_8000bb38((uint)puVar10,*(ushort *)((int)pfVar16 + 0x1e));
          FUN_80099c40((double)FLOAT_803e4698,puVar10,(int)*(short *)(pfVar16 + 8),0x28);
        }
      }
      if ((*(short *)((int)pfVar16 + 0x1a) == 0) && (puVar10[0x23] == 0x3d6)) {
        dVar20 = (double)FUN_80021754((float *)(iVar11 + 0x18),(float *)(puVar10 + 0xc));
        if (dVar20 < (double)FLOAT_803e46d4) {
          dVar20 = (double)(*(float *)(puVar10 + 8) - *(float *)(iVar11 + 0x10));
          if (dVar20 < (double)FLOAT_803e4690) {
            dVar20 = -dVar20;
          }
          if (dVar20 < (double)FLOAT_803e46d4) {
            uVar13 = FUN_80020078(0x1d9);
            if (uVar13 == 0) {
              FUN_800379bc(dVar20,dVar18,dVar21,param_4,param_5,param_6,param_7,param_8,iVar11,
                           0x60004,(uint)puVar10,1,in_r7,in_r8,in_r9,in_r10);
            }
            fVar2 = FLOAT_803e46d8;
            *(float *)(puVar10 + 6) =
                 FLOAT_803e46d8 * -*(float *)(puVar10 + 0x12) + *(float *)(puVar10 + 6);
            *(float *)(puVar10 + 10) =
                 fVar2 * -*(float *)(puVar10 + 0x16) + *(float *)(puVar10 + 10);
            FUN_8000bb38((uint)puVar10,0x45);
          }
        }
        iVar17 = FUN_80036974((int)puVar10,(undefined4 *)0x0,(int *)0x0,(uint *)0x0);
        if (iVar17 == 0xe) {
          *(undefined2 *)((int)pfVar16 + 0x1a) = 0xfa;
          FUN_8000bb38((uint)puVar10,0x40);
        }
      }
      else if ((*(short *)((int)pfVar16 + 0x1a) != 0) &&
              ((puVar10[0x23] == 0x3d6 &&
               (iVar17 = FUN_80036974((int)puVar10,(undefined4 *)0x0,(int *)0x0,(uint *)0x0),
               iVar17 == 0xe)))) {
        FUN_8000bb38((uint)puVar10,0x46);
        local_170 = DAT_803e4688;
        FUN_8029700c(iVar11,(uint)*(byte *)((int)&local_170 + (uint)*(byte *)((int)pfVar16 + 0x27)))
        ;
        *(undefined2 *)(pfVar16 + 4) = 0x50;
        *(undefined2 *)(pfVar16 + 5) = 0;
      }
    }
  }
LAB_80185bfc:
  FUN_80286888();
  return;
}

