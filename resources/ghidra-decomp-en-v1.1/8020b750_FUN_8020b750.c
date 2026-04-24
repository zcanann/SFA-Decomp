// Function: FUN_8020b750
// Entry: 8020b750
// Size: 2216 bytes

/* WARNING: Removing unreachable block (ram,0x8020bfd8) */
/* WARNING: Removing unreachable block (ram,0x8020bfd0) */
/* WARNING: Removing unreachable block (ram,0x8020b768) */
/* WARNING: Removing unreachable block (ram,0x8020b760) */

void FUN_8020b750(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)

{
  float fVar1;
  ushort uVar3;
  float fVar2;
  short sVar4;
  ushort *puVar5;
  char cVar12;
  int *piVar6;
  int iVar7;
  uint *puVar8;
  undefined2 *puVar9;
  uint uVar10;
  short *psVar11;
  undefined4 uVar13;
  float *pfVar14;
  int in_r7;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  undefined *puVar15;
  int iVar16;
  int iVar17;
  float *pfVar18;
  undefined8 extraout_f1;
  undefined8 uVar19;
  double dVar20;
  undefined8 extraout_f1_00;
  double dVar21;
  double dVar22;
  double in_f30;
  double in_f31;
  double in_ps30_1;
  double in_ps31_1;
  undefined4 local_88;
  float local_84;
  undefined4 local_80;
  float local_7c;
  undefined auStack_78 [19];
  char local_65 [8];
  char local_5d;
  longlong local_58;
  longlong local_50;
  float local_18;
  float fStack_14;
  float local_8;
  float fStack_4;
  
  local_8 = (float)in_f31;
  fStack_4 = (float)in_ps31_1;
  local_18 = (float)in_f30;
  fStack_14 = (float)in_ps30_1;
  puVar5 = (ushort *)FUN_80286838();
  pfVar18 = *(float **)(puVar5 + 0x5c);
  local_88 = 0x29;
  if ((*(byte *)(pfVar18 + 0x66) >> 4 & 1) != 0) {
    uVar19 = FUN_80008b74(extraout_f1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,puVar5
                          ,puVar5,0x144,0,in_r7,in_r8,in_r9,in_r10);
    uVar19 = FUN_80008b74(uVar19,param_2,param_3,param_4,param_5,param_6,param_7,param_8,puVar5,
                          puVar5,0x10d,0,in_r7,in_r8,in_r9,in_r10);
    FUN_80008b74(uVar19,param_2,param_3,param_4,param_5,param_6,param_7,param_8,puVar5,puVar5,0x10e,
                 0,in_r7,in_r8,in_r9,in_r10);
    FUN_800890e0((double)FLOAT_803e71a8,1);
    FUN_800551b4();
    in_r7 = *DAT_803dd71c;
    cVar12 = (**(code **)(in_r7 + 0x8c))((double)FLOAT_803e71f8,pfVar18 + 10,puVar5,&local_88,0xd);
    if (cVar12 != '\0') {
      in_r7 = *DAT_803dd71c;
      (**(code **)(in_r7 + 0x8c))((double)FLOAT_803e71f8,pfVar18 + 10,puVar5,&local_88,0);
    }
    *(float *)(puVar5 + 6) = pfVar18[0x24];
    *(float *)(puVar5 + 10) = pfVar18[0x26];
    *(float *)(puVar5 + 8) = pfVar18[0x25];
    *(byte *)(pfVar18 + 0x66) = *(byte *)(pfVar18 + 0x66) & 0xdf | 0x20;
    *(undefined *)(pfVar18 + 100) = 0;
    iVar17 = *(int *)(puVar5 + 0x5c);
    *(byte *)(iVar17 + 0x198) = *(byte *)(iVar17 + 0x198) & 0xdf | 0x20;
    (**(code **)(*DAT_803dd6e8 + 0x58))(*(undefined4 *)(iVar17 + 0x170),0x63e);
    (**(code **)(*DAT_803dd6e8 + 0x5c))(*(undefined4 *)(iVar17 + 0x170));
    *(byte *)(pfVar18 + 0x66) = *(byte *)(pfVar18 + 0x66) & 0xef;
    piVar6 = FUN_8001f58c(0,'\x01');
    pfVar18[0x58] = (float)piVar6;
    if (pfVar18[0x58] != 0.0) {
      FUN_8001dbf0((int)pfVar18[0x58],2);
      FUN_8001dbb4((int)pfVar18[0x58],0x40,0,0xff,0xff);
      FUN_8001dadc((int)pfVar18[0x58],0x40,0,0xff,0xff);
      in_r8 = 0x5a;
      FUN_8001d7f4((double)FLOAT_803e71fc,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                   pfVar18[0x58],0,0x40,0,0x80,0x5a,in_r9,in_r10);
      FUN_8001dcfc((double)FLOAT_803e71dc,(double)FLOAT_803e71d8,(int)pfVar18[0x58]);
      FUN_8001dc18((int)pfVar18[0x58],0);
      FUN_8001dc30((double)FLOAT_803e71b8,(int)pfVar18[0x58],'\x01');
      FUN_8001db7c((int)pfVar18[0x58],0x40,0,0x80,0x40);
      in_r7 = 0x40;
      FUN_8001daa4((int)pfVar18[0x58],0x40,0,0x80,0x40);
      FUN_8001d6e4((int)pfVar18[0x58],2,0x28);
      FUN_8001de04((int)pfVar18[0x58],1);
      FUN_8001d7d8((double)FLOAT_803e71e8,(int)pfVar18[0x58]);
    }
  }
  dVar20 = (double)*pfVar18;
  FUN_80137cd0();
  dVar22 = (double)FLOAT_803e71b8;
  pfVar14 = pfVar18 + 0x65;
  iVar17 = FUN_802227b0(dVar20,(double)FLOAT_803e7200,dVar22,puVar5,pfVar18 + 10,1,pfVar14);
  if ((*(byte *)(pfVar18 + 0x66) >> 6 & 1) == 0) {
    FUN_80222ba0((double)FLOAT_803e71e0,(double)FLOAT_803e7204,puVar5,(float *)(puVar5 + 0x12),0x2d)
    ;
  }
  else {
    iVar7 = FUN_8002bac4();
    if (iVar7 != 0) {
      iVar7 = FUN_800386e0(puVar5,iVar7,(float *)0x0);
      sVar4 = (short)iVar7;
      if (sVar4 < -0x200) {
        sVar4 = -0x200;
      }
      else if (0x200 < sVar4) {
        sVar4 = 0x200;
      }
      *puVar5 = *puVar5 + sVar4;
      uVar3 = puVar5[1];
      if (uVar3 != 0) {
        if ((short)uVar3 < -0x100) {
          uVar3 = 0xff00;
        }
        else if (0x100 < (short)uVar3) {
          uVar3 = 0x100;
        }
        puVar5[1] = puVar5[1] - uVar3;
      }
      uVar3 = puVar5[2];
      if (uVar3 != 0) {
        if ((short)uVar3 < -0x100) {
          uVar3 = 0xff00;
        }
        else if (0x100 < (short)uVar3) {
          uVar3 = 0x100;
        }
        puVar5[2] = puVar5[2] - uVar3;
      }
    }
  }
  if (iVar17 != 0) {
    FUN_8020b110(puVar5,(int)pfVar18,iVar17);
  }
  dVar20 = FUN_80247f54((float *)(puVar5 + 0x12));
  dVar21 = (double)FLOAT_803dc074;
  iVar17 = FUN_8002fb40((double)((float)(dVar20 / (double)pfVar18[0x59]) + FLOAT_803e7208),dVar21);
  uVar19 = extraout_f1_00;
  if (iVar17 != 0) {
    if (pfVar18[0x5a] == 0.0) {
      FUN_80035ea4((int)puVar5);
      *(byte *)(pfVar18 + 0x66) = *(byte *)(pfVar18 + 0x66) & 0xfb;
      *(byte *)(pfVar18 + 0x66) = *(byte *)(pfVar18 + 0x66) & 0xf7;
      if ((*(byte *)(pfVar18 + 0x66) >> 6 & 1) == 0) {
        pfVar18[0x59] = FLOAT_803e71cc;
        FUN_8002f66c((int)puVar5,0x28);
        uVar13 = 0x10;
      }
      else {
        uVar13 = FUN_8020ac20((short *)puVar5,pfVar18 + 0x59);
      }
      uVar19 = FUN_8003042c((double)FLOAT_803e71a8,dVar21,dVar22,param_4,param_5,param_6,param_7,
                            param_8,puVar5,uVar13,0,pfVar14,in_r7,in_r8,in_r9,in_r10);
    }
    else {
      uVar19 = FUN_8003042c((double)FLOAT_803e71a8,dVar21,dVar22,param_4,param_5,param_6,param_7,
                            param_8,puVar5,pfVar18[0x5a],0,pfVar14,in_r7,in_r8,in_r9,in_r10);
    }
    iVar17 = FUN_80080100((int *)&DAT_8032abf8,5,(int)pfVar18[0x5a]);
    if (iVar17 != -1) {
      fVar2 = pfVar18[0x5a];
      if (fVar2 == 2.8026e-44) {
        if ((*(byte *)(pfVar18 + 0x66) >> 3 & 1) == 0) {
          uVar19 = FUN_80035eec((int)puVar5,5,1,0);
          pfVar18[0x5a] = 2.94273e-44;
          pfVar18[0x59] = FLOAT_803e720c;
        }
        else {
          pfVar18[0x5a] = 0.0;
        }
      }
      else if ((int)fVar2 < 0x14) {
        if (fVar2 == 2.52234e-44) {
          *(byte *)(pfVar18 + 0x66) = *(byte *)(pfVar18 + 0x66) & 0xbf;
          pfVar18[0x5a] = 0.0;
        }
        else if (0x11 < (int)fVar2) {
          pfVar18[0x5a] = 3.08286e-44;
          pfVar18[0x59] = FLOAT_803e71cc;
        }
      }
      else if (fVar2 == 3.08286e-44) {
        pfVar18[0x5a] = 3.08286e-44;
        pfVar18[0x59] = FLOAT_803e720c;
      }
      else if ((int)fVar2 < 0x16) {
        pfVar18[0x5a] = 0.0;
        pfVar18[0x59] = FLOAT_803e71ac;
        *(byte *)(pfVar18 + 0x66) = *(byte *)(pfVar18 + 0x66) & 0xfb | 4;
      }
    }
  }
  puVar15 = auStack_78;
  for (iVar17 = 0; iVar17 < local_5d; iVar17 = iVar17 + 1) {
    cVar12 = puVar15[0x13];
    if (cVar12 == '\a') {
      uVar19 = FUN_8000bb38((uint)puVar5,0x481);
    }
    else if ((cVar12 < '\a') && (cVar12 == '\0')) {
      uVar19 = FUN_8000bb38((uint)puVar5,0x481);
    }
    puVar15 = puVar15 + 1;
  }
  iVar17 = FUN_80080434(pfVar18 + 4);
  if (iVar17 != 0) {
    FUN_8020ad98(uVar19,dVar21,dVar22,param_4,param_5,param_6,param_7,param_8,puVar5,pfVar18,
                 (int)pfVar18[0x5d]);
    if (pfVar18[5] != FLOAT_803e71a8) {
      iVar17 = (int)pfVar18[5];
      local_58 = (longlong)iVar17;
      FUN_80080404(pfVar18 + 4,(short)iVar17);
    }
  }
  if ((puVar5[0x58] & 0x800) == 0) {
    pfVar18[7] = *(float *)(puVar5 + 6);
    pfVar18[8] = *(float *)(puVar5 + 8) - FLOAT_803e71f4;
    pfVar18[9] = *(float *)(puVar5 + 10);
  }
  FUN_8002ba34((double)*(float *)(puVar5 + 0x12),(double)*(float *)(puVar5 + 0x14),
               (double)*(float *)(puVar5 + 0x16),(int)puVar5);
  if ((*(byte *)(pfVar18 + 0x66) >> 5 & 1) != 0) {
    (**(code **)(*DAT_803dd6e8 + 0x5c))(pfVar18[0x5c]);
  }
  fVar2 = FLOAT_803e71a8;
  if (FLOAT_803e71a8 != pfVar18[0x5e]) {
    pfVar18[0x5f] = -(FLOAT_803e7210 * FLOAT_803dc074 - pfVar18[0x5f]);
    pfVar18[0x5e] = pfVar18[0x5e] + pfVar18[0x5f];
    fVar1 = pfVar18[0x5e];
    if ((fVar2 <= fVar1) && (fVar2 = fVar1, FLOAT_803e71e8 < fVar1)) {
      fVar2 = FLOAT_803e71e8;
    }
    pfVar18[0x5e] = fVar2;
    dVar20 = (double)pfVar18[0x60];
    dVar22 = (double)pfVar18[0x5e];
    puVar8 = FUN_80039598();
    iVar17 = (int)((double)FLOAT_803e71c8 * dVar22);
    local_58 = (longlong)iVar17;
    iVar7 = (int)((double)FLOAT_803e71c8 * (double)(float)(dVar22 * dVar20));
    local_50 = (longlong)iVar7;
    iVar16 = 0;
    do {
      puVar9 = (undefined2 *)FUN_800396d0((int)puVar5,*puVar8);
      if (puVar9 != (undefined2 *)0x0) {
        puVar9[1] = (short)iVar7;
        *puVar9 = (short)iVar17;
        puVar9[2] = 0;
      }
      puVar8 = puVar8 + 1;
      iVar16 = iVar16 + 1;
    } while (iVar16 < 5);
  }
  uVar10 = FUN_8008038c(200);
  if ((uVar10 != 0) && ((*(byte *)(pfVar18 + 0x66) >> 6 & 1) != 0)) {
    FUN_80039368((uint)puVar5,(undefined *)(pfVar18 + 0x4c),0x2ff);
  }
  FUN_80039030((int)puVar5,(char *)(pfVar18 + 0x4c));
  if ((*(byte *)(pfVar18 + 0x66) >> 2 & 1) == 0) {
    FUN_8020aa14((int)puVar5,(int)pfVar18);
  }
  else {
    iVar17 = FUN_8002bac4();
    psVar11 = (short *)FUN_800396d0((int)puVar5,0xe);
    if (psVar11 != (short *)0x0) {
      FUN_80038524(puVar5,4,&local_84,&local_80,&local_7c,0);
      FUN_80247eb8((float *)(iVar17 + 0xc),&local_84,&local_84);
      FUN_80293900((double)(local_84 * local_84 + local_7c * local_7c));
      iVar17 = FUN_80021884();
      sVar4 = (short)iVar17 - *psVar11;
      if (0x8000 < sVar4) {
        sVar4 = sVar4 + 1;
      }
      if (sVar4 < -0x8000) {
        sVar4 = sVar4 + -1;
      }
      iVar16 = (int)sVar4;
      iVar7 = (uint)DAT_803dc070 * 0x100;
      iVar17 = (uint)DAT_803dc070 * -0x100;
      if ((iVar17 <= iVar16) && (iVar17 = iVar16, iVar7 < iVar16)) {
        iVar17 = iVar7;
      }
      *psVar11 = *psVar11 + (short)iVar17;
    }
  }
  FUN_80286884();
  return;
}

