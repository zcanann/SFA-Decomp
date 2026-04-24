// Function: FUN_8020b0f0
// Entry: 8020b0f0
// Size: 2192 bytes

/* WARNING: Removing unreachable block (ram,0x8020b958) */
/* WARNING: Removing unreachable block (ram,0x8020b960) */

void FUN_8020b0f0(void)

{
  float fVar1;
  short *psVar2;
  char cVar9;
  float fVar3;
  int iVar4;
  short sVar8;
  undefined4 *puVar5;
  undefined2 *puVar6;
  short *psVar7;
  undefined4 uVar10;
  undefined *puVar11;
  int iVar12;
  int iVar13;
  float *pfVar14;
  undefined4 uVar15;
  double dVar16;
  undefined8 uVar17;
  undefined8 in_f30;
  undefined8 in_f31;
  double dVar18;
  undefined4 local_88;
  float local_84;
  float local_80;
  float local_7c;
  undefined auStack120 [19];
  char local_65 [8];
  char local_5d;
  longlong local_58;
  longlong local_50;
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar15 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  __psq_st0(auStack24,(int)((ulonglong)in_f30 >> 0x20),0);
  __psq_st1(auStack24,(int)in_f30,0);
  psVar2 = (short *)FUN_802860d4();
  pfVar14 = *(float **)(psVar2 + 0x5c);
  local_88 = 0x29;
  if ((*(byte *)(pfVar14 + 0x66) >> 4 & 1) != 0) {
    FUN_80008b74(psVar2,psVar2,0x144,0);
    FUN_80008b74(psVar2,psVar2,0x10d,0);
    FUN_80008b74(psVar2,psVar2,0x10e,0);
    FUN_80088e54((double)FLOAT_803e6510,1);
    FUN_80055038();
    cVar9 = (**(code **)(*DAT_803dca9c + 0x8c))
                      ((double)FLOAT_803e6560,pfVar14 + 10,psVar2,&local_88,0xd);
    if (cVar9 != '\0') {
      (**(code **)(*DAT_803dca9c + 0x8c))((double)FLOAT_803e6560,pfVar14 + 10,psVar2,&local_88,0);
    }
    *(float *)(psVar2 + 6) = pfVar14[0x24];
    *(float *)(psVar2 + 10) = pfVar14[0x26];
    *(float *)(psVar2 + 8) = pfVar14[0x25];
    *(byte *)(pfVar14 + 0x66) = *(byte *)(pfVar14 + 0x66) & 0xdf | 0x20;
    *(undefined *)(pfVar14 + 100) = 0;
    iVar13 = *(int *)(psVar2 + 0x5c);
    *(byte *)(iVar13 + 0x198) = *(byte *)(iVar13 + 0x198) & 0xdf | 0x20;
    (**(code **)(*DAT_803dca68 + 0x58))(*(undefined4 *)(iVar13 + 0x170),0x63e);
    (**(code **)(*DAT_803dca68 + 0x5c))(*(undefined4 *)(iVar13 + 0x170));
    *(byte *)(pfVar14 + 0x66) = *(byte *)(pfVar14 + 0x66) & 0xef;
    fVar3 = (float)FUN_8001f4c8(0,1);
    pfVar14[0x58] = fVar3;
    if (pfVar14[0x58] != 0.0) {
      FUN_8001db2c(pfVar14[0x58],2);
      FUN_8001daf0(pfVar14[0x58],0x40,0,0xff,0xff);
      FUN_8001da18(pfVar14[0x58],0x40,0,0xff,0xff);
      FUN_8001d730((double)FLOAT_803e6564,pfVar14[0x58],0,0x40,0,0x80,0x5a);
      FUN_8001dc38((double)FLOAT_803e6544,(double)FLOAT_803e6540,pfVar14[0x58]);
      FUN_8001db54(pfVar14[0x58],0);
      FUN_8001db6c((double)FLOAT_803e6520,pfVar14[0x58],1);
      FUN_8001dab8(pfVar14[0x58],0x40,0,0x80,0x40);
      FUN_8001d9e0(pfVar14[0x58],0x40,0,0x80,0x40);
      FUN_8001d620(pfVar14[0x58],2,0x28);
      FUN_8001dd40(pfVar14[0x58],1);
      FUN_8001d714((double)FLOAT_803e6550,pfVar14[0x58]);
    }
  }
  iVar13 = FUN_80222160((double)*pfVar14,(double)FLOAT_803e6568,(double)FLOAT_803e6520,psVar2,
                        pfVar14 + 10,1,pfVar14 + 0x65);
  if ((*(byte *)(pfVar14 + 0x66) >> 6 & 1) == 0) {
    FUN_80222550((double)FLOAT_803e6548,(double)FLOAT_803e656c,psVar2,psVar2 + 0x12,0x2d);
  }
  else {
    iVar4 = FUN_8002b9ec();
    if (iVar4 != 0) {
      sVar8 = FUN_800385e8(psVar2,iVar4,0);
      if (sVar8 < -0x200) {
        sVar8 = -0x200;
      }
      else if (0x200 < sVar8) {
        sVar8 = 0x200;
      }
      *psVar2 = *psVar2 + sVar8;
      sVar8 = psVar2[1];
      if (sVar8 != 0) {
        if (sVar8 < -0x100) {
          sVar8 = -0x100;
        }
        else if (0x100 < sVar8) {
          sVar8 = 0x100;
        }
        psVar2[1] = psVar2[1] - sVar8;
      }
      sVar8 = psVar2[2];
      if (sVar8 != 0) {
        if (sVar8 < -0x100) {
          sVar8 = -0x100;
        }
        else if (0x100 < sVar8) {
          sVar8 = 0x100;
        }
        psVar2[2] = psVar2[2] - sVar8;
      }
    }
  }
  if (iVar13 != 0) {
    FUN_8020aab0(psVar2,pfVar14,iVar13);
  }
  dVar16 = (double)FUN_802477f0(psVar2 + 0x12);
  iVar13 = FUN_8002fa48((double)((float)(dVar16 / (double)pfVar14[0x59]) + FLOAT_803e6570),
                        (double)FLOAT_803db414,psVar2,auStack120);
  if (iVar13 != 0) {
    if (pfVar14[0x5a] == 0.0) {
      FUN_80035dac(psVar2);
      *(byte *)(pfVar14 + 0x66) = *(byte *)(pfVar14 + 0x66) & 0xfb;
      *(byte *)(pfVar14 + 0x66) = *(byte *)(pfVar14 + 0x66) & 0xf7;
      if ((*(byte *)(pfVar14 + 0x66) >> 6 & 1) == 0) {
        pfVar14[0x59] = FLOAT_803e6534;
        FUN_8002f574(psVar2,0x28);
        uVar10 = 0x10;
      }
      else {
        uVar10 = FUN_8020a5e8(psVar2,pfVar14 + 0x59);
      }
      FUN_80030334((double)FLOAT_803e6510,psVar2,uVar10,0);
    }
    else {
      FUN_80030334((double)FLOAT_803e6510,psVar2,pfVar14[0x5a],0);
    }
    iVar13 = FUN_8007fe74(&DAT_80329fb8,5,pfVar14[0x5a]);
    if (iVar13 != -1) {
      fVar3 = pfVar14[0x5a];
      if (fVar3 == 2.802597e-44) {
        if ((*(byte *)(pfVar14 + 0x66) >> 3 & 1) == 0) {
          FUN_80035df4(psVar2,5,1,0);
          pfVar14[0x5a] = 2.942727e-44;
          pfVar14[0x59] = FLOAT_803e6574;
        }
        else {
          pfVar14[0x5a] = 0.0;
        }
      }
      else if ((int)fVar3 < 0x14) {
        if (fVar3 == 2.522337e-44) {
          *(byte *)(pfVar14 + 0x66) = *(byte *)(pfVar14 + 0x66) & 0xbf;
          pfVar14[0x5a] = 0.0;
        }
        else if (0x11 < (int)fVar3) {
          pfVar14[0x5a] = 3.082857e-44;
          pfVar14[0x59] = FLOAT_803e6534;
        }
      }
      else if (fVar3 == 3.082857e-44) {
        pfVar14[0x5a] = 3.082857e-44;
        pfVar14[0x59] = FLOAT_803e6574;
      }
      else if ((int)fVar3 < 0x16) {
        pfVar14[0x5a] = 0.0;
        pfVar14[0x59] = FLOAT_803e6514;
        *(byte *)(pfVar14 + 0x66) = *(byte *)(pfVar14 + 0x66) & 0xfb | 4;
      }
    }
  }
  puVar11 = auStack120;
  for (iVar13 = 0; iVar13 < local_5d; iVar13 = iVar13 + 1) {
    cVar9 = puVar11[0x13];
    if (cVar9 == '\a') {
      FUN_8000bb18(psVar2,0x481);
    }
    else if ((cVar9 < '\a') && (cVar9 == '\0')) {
      FUN_8000bb18(psVar2,0x481);
    }
    puVar11 = puVar11 + 1;
  }
  iVar13 = FUN_800801a8(pfVar14 + 4);
  if (iVar13 != 0) {
    FUN_8020a760(psVar2,pfVar14,pfVar14[0x5d]);
    if (pfVar14[5] != FLOAT_803e6510) {
      iVar13 = (int)pfVar14[5];
      local_58 = (longlong)iVar13;
      FUN_80080178(pfVar14 + 4,iVar13);
    }
  }
  if ((psVar2[0x58] & 0x800U) == 0) {
    pfVar14[7] = *(float *)(psVar2 + 6);
    pfVar14[8] = *(float *)(psVar2 + 8) - FLOAT_803e655c;
    pfVar14[9] = *(float *)(psVar2 + 10);
  }
  FUN_8002b95c((double)*(float *)(psVar2 + 0x12),(double)*(float *)(psVar2 + 0x14),
               (double)*(float *)(psVar2 + 0x16),psVar2);
  if ((*(byte *)(pfVar14 + 0x66) >> 5 & 1) != 0) {
    (**(code **)(*DAT_803dca68 + 0x5c))(pfVar14[0x5c]);
  }
  fVar3 = FLOAT_803e6510;
  if (FLOAT_803e6510 != pfVar14[0x5e]) {
    pfVar14[0x5f] = -(FLOAT_803e6578 * FLOAT_803db414 - pfVar14[0x5f]);
    pfVar14[0x5e] = pfVar14[0x5e] + pfVar14[0x5f];
    fVar1 = pfVar14[0x5e];
    if ((fVar3 <= fVar1) && (fVar3 = fVar1, FLOAT_803e6550 < fVar1)) {
      fVar3 = FLOAT_803e6550;
    }
    pfVar14[0x5e] = fVar3;
    dVar16 = (double)pfVar14[0x60];
    dVar18 = (double)pfVar14[0x5e];
    puVar5 = (undefined4 *)FUN_800394a0();
    iVar13 = (int)((double)FLOAT_803e6530 * dVar18);
    local_58 = (longlong)iVar13;
    iVar4 = (int)((double)FLOAT_803e6530 * (double)(float)(dVar18 * dVar16));
    local_50 = (longlong)iVar4;
    iVar12 = 0;
    do {
      puVar6 = (undefined2 *)FUN_800395d8(psVar2,*puVar5);
      if (puVar6 != (undefined2 *)0x0) {
        puVar6[1] = (short)iVar4;
        *puVar6 = (short)iVar13;
        puVar6[2] = 0;
      }
      puVar5 = puVar5 + 1;
      iVar12 = iVar12 + 1;
    } while (iVar12 < 5);
  }
  iVar13 = FUN_80080100(200);
  if ((iVar13 != 0) && ((*(byte *)(pfVar14 + 0x66) >> 6 & 1) != 0)) {
    FUN_80039270(psVar2,pfVar14 + 0x4c,0x2ff);
  }
  FUN_80038f38(psVar2,pfVar14 + 0x4c);
  if ((*(byte *)(pfVar14 + 0x66) >> 2 & 1) == 0) {
    FUN_8020a3dc(psVar2,pfVar14);
  }
  else {
    iVar13 = FUN_8002b9ec();
    psVar7 = (short *)FUN_800395d8(psVar2,0xe);
    if (psVar7 != (short *)0x0) {
      FUN_8003842c(psVar2,4,&local_84,&local_80,&local_7c,0);
      FUN_80247754(iVar13 + 0xc,&local_84,&local_84);
      uVar17 = FUN_802931a0((double)(local_84 * local_84 + local_7c * local_7c));
      sVar8 = FUN_800217c0((double)local_80,uVar17);
      sVar8 = sVar8 - *psVar7;
      if (0x8000 < sVar8) {
        sVar8 = sVar8 + 1;
      }
      if (sVar8 < -0x8000) {
        sVar8 = sVar8 + -1;
      }
      iVar12 = (int)sVar8;
      iVar4 = (uint)DAT_803db410 * 0x100;
      iVar13 = (uint)DAT_803db410 * -0x100;
      if ((iVar13 <= iVar12) && (iVar13 = iVar12, iVar4 < iVar12)) {
        iVar13 = iVar4;
      }
      *psVar7 = *psVar7 + (short)iVar13;
    }
  }
  __psq_l0(auStack8,uVar15);
  __psq_l1(auStack8,uVar15);
  __psq_l0(auStack24,uVar15);
  __psq_l1(auStack24,uVar15);
  FUN_80286120();
  return;
}

