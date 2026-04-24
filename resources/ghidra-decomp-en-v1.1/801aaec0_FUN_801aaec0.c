// Function: FUN_801aaec0
// Entry: 801aaec0
// Size: 2860 bytes

/* WARNING: Removing unreachable block (ram,0x801ab9cc) */
/* WARNING: Removing unreachable block (ram,0x801aaed0) */

void FUN_801aaec0(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)

{
  bool bVar1;
  short *psVar2;
  int iVar3;
  byte bVar6;
  uint uVar4;
  undefined2 *puVar5;
  float *pfVar7;
  uint *in_r7;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  int iVar8;
  int iVar9;
  short unaff_r26;
  short unaff_r27;
  int unaff_r28;
  int *piVar10;
  double extraout_f1;
  double dVar11;
  double dVar12;
  double in_f31;
  double in_ps31_1;
  int local_58;
  float local_54 [5];
  undefined8 local_40;
  float local_8;
  float fStack_4;
  
  local_8 = (float)in_f31;
  fStack_4 = (float)in_ps31_1;
  psVar2 = (short *)FUN_80286834();
  piVar10 = *(int **)(psVar2 + 0x5c);
  if (((&DAT_80324048)[*(byte *)(piVar10 + 4)] & 1) == 0) {
    *(byte *)((int)psVar2 + 0xaf) = *(byte *)((int)psVar2 + 0xaf) & 0xf7;
  }
  else {
    *(byte *)((int)psVar2 + 0xaf) = *(byte *)((int)psVar2 + 0xaf) | 8;
  }
  iVar8 = piVar10[2];
  dVar11 = extraout_f1;
  if (iVar8 != 0) {
    dVar11 = FUN_8014ca48(iVar8);
    if ((double)FLOAT_803e5318 < dVar11) {
      uVar4 = FUN_80020078((int)*(short *)(*(int *)(iVar8 + 0x4c) + 0x18));
      if (uVar4 == 0) {
        bVar1 = true;
      }
      else {
        bVar1 = false;
      }
    }
    else {
      bVar1 = false;
    }
    if (bVar1) {
      iVar8 = piVar10[3];
      dVar11 = FUN_8014ca48(iVar8);
      if ((double)FLOAT_803e5318 < dVar11) {
        uVar4 = FUN_80020078((int)*(short *)(*(int *)(iVar8 + 0x4c) + 0x18));
        if (uVar4 == 0) {
          bVar1 = true;
        }
        else {
          bVar1 = false;
        }
      }
      else {
        bVar1 = false;
      }
      if (!bVar1) goto LAB_801ab118;
      dVar11 = FUN_80021730((float *)(piVar10[1] + 0x18),(float *)(piVar10[3] + 0x18));
      dVar12 = FUN_80021730((float *)(piVar10[1] + 0x18),(float *)(piVar10[2] + 0x18));
      if (dVar11 <= dVar12) {
        iVar8 = piVar10[3];
        iVar9 = piVar10[2];
      }
      else {
        iVar8 = piVar10[2];
        iVar9 = piVar10[3];
      }
      dVar11 = FUN_80021730((float *)(psVar2 + 0xc),(float *)(piVar10[1] + 0x18));
      if (((((double)FLOAT_803e531c <= dVar11) &&
           (iVar3 = FUN_80296878(piVar10[1]), iVar3 != piVar10[2])) &&
          (iVar3 = FUN_80296878(piVar10[1]), iVar3 != piVar10[3])) ||
         (bVar6 = FUN_80296434(piVar10[1]), bVar6 != 0)) {
        for (bVar6 = 0; bVar6 < 2; bVar6 = bVar6 + 1) {
          dVar11 = FUN_80021730((float *)(psVar2 + 0xc),(float *)(piVar10[bVar6 + 2] + 0x18));
          local_54[bVar6] = (float)dVar11;
          FUN_8014cae4(piVar10[bVar6 + 2],psVar2);
        }
        in_f31 = (double)local_54[1];
        if (in_f31 <= (double)local_54[0]) {
          unaff_r28 = piVar10[3];
        }
        else {
          unaff_r28 = piVar10[2];
          in_f31 = (double)local_54[0];
        }
      }
      else {
        iVar3 = FUN_80296878(piVar10[1]);
        unaff_r28 = iVar9;
        if (iVar3 == iVar9) {
          unaff_r28 = iVar8;
          iVar8 = iVar9;
        }
        FUN_8014cae4(iVar8,piVar10[1]);
        FUN_8014cae4(unaff_r28,psVar2);
        in_f31 = FUN_80021730((float *)(psVar2 + 0xc),(float *)(unaff_r28 + 0x18));
      }
    }
    else {
LAB_801ab118:
      iVar8 = piVar10[2];
      dVar11 = FUN_8014ca48(iVar8);
      if ((double)FLOAT_803e5318 < dVar11) {
        uVar4 = FUN_80020078((int)*(short *)(*(int *)(iVar8 + 0x4c) + 0x18));
        if (uVar4 == 0) {
          bVar1 = true;
        }
        else {
          bVar1 = false;
        }
      }
      else {
        bVar1 = false;
      }
      unaff_r28 = 0;
      if (bVar1) {
        unaff_r28 = piVar10[2];
      }
      iVar8 = piVar10[3];
      dVar11 = FUN_8014ca48(iVar8);
      if ((double)FLOAT_803e5318 < dVar11) {
        uVar4 = FUN_80020078((int)*(short *)(*(int *)(iVar8 + 0x4c) + 0x18));
        if (uVar4 == 0) {
          bVar1 = true;
        }
        else {
          bVar1 = false;
        }
      }
      else {
        bVar1 = false;
      }
      if (bVar1) {
        unaff_r28 = piVar10[3];
      }
      if (unaff_r28 == 0) {
        unaff_r28 = piVar10[1];
        in_f31 = (double)FLOAT_803e530c;
      }
      else {
        dVar11 = FUN_80021730((float *)(piVar10[1] + 0x18),(float *)(unaff_r28 + 0x18));
        dVar12 = FUN_80021730((float *)(psVar2 + 0xc),(float *)(unaff_r28 + 0x18));
        if (((dVar12 < dVar11) && (iVar8 = FUN_80296878(piVar10[1]), iVar8 != unaff_r28)) ||
           (bVar6 = FUN_80296434(piVar10[1]), bVar6 != 0)) {
          FUN_8014cae4(unaff_r28,psVar2);
        }
        else {
          FUN_8014cae4(unaff_r28,piVar10[1]);
        }
        in_f31 = FUN_80021730((float *)(psVar2 + 0xc),(float *)(unaff_r28 + 0x18));
      }
    }
    dVar11 = -(double)(*(float *)(unaff_r28 + 0xc) - *(float *)(psVar2 + 6));
    param_2 = -(double)(*(float *)(unaff_r28 + 0x14) - *(float *)(psVar2 + 10));
    iVar8 = FUN_80021884();
    unaff_r27 = (short)iVar8;
    unaff_r26 = *psVar2 - unaff_r27;
    if (0x8000 < unaff_r26) {
      unaff_r26 = unaff_r26 + 1;
    }
    if (unaff_r26 < -0x8000) {
      unaff_r26 = unaff_r26 + -1;
    }
    if (unaff_r26 < 0x1001) {
      if (unaff_r26 < -0x1000) {
        *(byte *)((int)piVar10 + 0x11) = *(byte *)((int)piVar10 + 0x11) | 2;
      }
      else {
        *(byte *)((int)piVar10 + 0x11) = *(byte *)((int)piVar10 + 0x11) & 0xfd;
      }
    }
    else {
      *(byte *)((int)piVar10 + 0x11) = *(byte *)((int)piVar10 + 0x11) | 2;
    }
  }
  if (*(byte *)(piVar10 + 4) < 0xc) {
    piVar10[5] = (int)((float)piVar10[5] - FLOAT_803dc074);
    dVar11 = (double)(float)piVar10[5];
    if (dVar11 < (double)FLOAT_803e5318) {
      uVar4 = FUN_80022264(0xb4,300);
      local_40 = (double)CONCAT44(0x43300000,uVar4 ^ 0x80000000);
      piVar10[5] = (int)(float)(local_40 - DOUBLE_803e5338);
      dVar11 = (double)FUN_8000bb38((uint)psVar2,0x134);
    }
  }
  switch(*(undefined *)(piVar10 + 4)) {
  case 0:
    uVar4 = FUN_80020078(9);
    if (uVar4 == 0) {
      uVar4 = FUN_8002e144();
      if ((uVar4 & 0xff) != 0) {
        puVar5 = FUN_8002becc(0x20,0x6f1);
        in_r7 = *(uint **)(psVar2 + 0x18);
        iVar8 = FUN_8002e088(dVar11,param_2,param_3,param_4,param_5,param_6,param_7,param_8,puVar5,5
                             ,0xff,0xffffffff,in_r7,in_r8,in_r9,in_r10);
        *piVar10 = iVar8;
        FUN_80037e24((int)psVar2,*piVar10,0);
      }
      iVar8 = FUN_8002bac4();
      piVar10[1] = iVar8;
      iVar8 = FUN_8002e1ac(0x45d7d);
      piVar10[2] = iVar8;
      iVar8 = FUN_8002e1ac(0x45d7f);
      piVar10[3] = iVar8;
      *(undefined *)(piVar10 + 4) = 1;
      uVar4 = FUN_80022264(0xb4,300);
      local_40 = (double)CONCAT44(0x43300000,uVar4 ^ 0x80000000);
      piVar10[5] = (int)(float)(local_40 - DOUBLE_803e5338);
    }
    else {
      *(undefined *)(piVar10 + 4) = 0xe;
    }
    break;
  case 1:
    if ((FLOAT_803e5314 < *(float *)(psVar2 + 0x4c)) && (*(float *)(psVar2 + 0x4c) < FLOAT_803e5320)
       ) {
      if (unaff_r26 < 0x401) {
        if (unaff_r26 < -0x400) {
          local_40 = (double)(longlong)(int)(FLOAT_803e5324 * FLOAT_803dc074);
          *psVar2 = *psVar2 + (short)(int)(FLOAT_803e5324 * FLOAT_803dc074);
        }
        else {
          *psVar2 = unaff_r27;
        }
      }
      else {
        local_40 = (double)(longlong)(int)(FLOAT_803e5324 * FLOAT_803dc074);
        *psVar2 = *psVar2 - (short)(int)(FLOAT_803e5324 * FLOAT_803dc074);
      }
    }
    if ((*(byte *)((int)piVar10 + 0x11) & 1) != 0) {
      FUN_801aae2c(in_f31,(int)piVar10,unaff_r28);
    }
    break;
  case 2:
    if ((*(byte *)((int)piVar10 + 0x11) & 1) != 0) {
      if ((double)FLOAT_803e5310 <= in_f31) {
        *(undefined *)(piVar10 + 4) = 3;
      }
      else {
        *(undefined *)(piVar10 + 4) = 4;
      }
    }
    break;
  case 3:
    if ((*(byte *)((int)piVar10 + 0x11) & 1) != 0) {
      *(undefined *)(piVar10 + 4) = 4;
    }
    break;
  case 4:
    if ((*(byte *)((int)piVar10 + 0x11) & 1) != 0) {
      FUN_801aae2c(in_f31,(int)piVar10,unaff_r28);
    }
    break;
  case 5:
    if (*(short *)(unaff_r28 + 0xa0) != 0x19) {
      *(undefined *)(piVar10 + 4) = 7;
    }
    if ((*(byte *)((int)piVar10 + 0x11) & 1) != 0) {
      *(undefined *)(piVar10 + 4) = 6;
    }
    break;
  case 6:
    if (*(short *)(unaff_r28 + 0xa0) != 0x19) {
      *(undefined *)(piVar10 + 4) = 7;
    }
    break;
  case 7:
    if ((*(short *)(unaff_r28 + 0xa0) != 0x18) || (*(float *)(unaff_r28 + 0x98) <= FLOAT_803e5314))
    {
      if (*(short *)(unaff_r28 + 0xa0) == 0x19) {
        *(undefined *)(piVar10 + 4) = 5;
      }
      else if ((*(byte *)((int)piVar10 + 0x11) & 1) != 0) {
        FUN_801aae2c(in_f31,(int)piVar10,unaff_r28);
      }
    }
    else {
      *(undefined *)(piVar10 + 4) = 8;
    }
    break;
  case 8:
    bVar1 = *(short *)(unaff_r28 + 0xa0) != 0x18;
    if ((bVar1) || ((!bVar1 && (*(float *)(unaff_r28 + 0x98) < FLOAT_803e5314)))) {
      *(undefined *)(piVar10 + 4) = 10;
    }
    if ((*(byte *)((int)piVar10 + 0x11) & 1) != 0) {
      *(undefined *)(piVar10 + 4) = 9;
    }
    break;
  case 9:
    bVar1 = *(short *)(unaff_r28 + 0xa0) != 0x18;
    if ((bVar1) || ((!bVar1 && (*(float *)(unaff_r28 + 0x98) < FLOAT_803e5314)))) {
      *(undefined *)(piVar10 + 4) = 10;
    }
    break;
  case 10:
    if ((*(short *)(unaff_r28 + 0xa0) != 0x18) || (*(float *)(unaff_r28 + 0x98) <= FLOAT_803e5314))
    {
      if (*(short *)(unaff_r28 + 0xa0) == 0x19) {
        *(undefined *)(piVar10 + 4) = 5;
      }
      else if ((*(byte *)((int)piVar10 + 0x11) & 1) != 0) {
        FUN_801aae2c(in_f31,(int)piVar10,unaff_r28);
      }
    }
    else {
      *(undefined *)(piVar10 + 4) = 8;
    }
    break;
  case 0xb:
    FUN_801aae2c(in_f31,(int)piVar10,unaff_r28);
    break;
  case 0xc:
    uVar4 = FUN_80020078(9);
    if (uVar4 == 0) {
      iVar8 = FUN_8003811c((int)psVar2);
      if (iVar8 == 0) {
        if ((*(byte *)((int)piVar10 + 0x11) & 2) != 0) {
          *(undefined *)(piVar10 + 4) = 0xd;
        }
      }
      else {
        FUN_800201ac(9,1);
      }
    }
    else {
      uVar4 = FUN_80020078(0x24);
      if (uVar4 != 0) {
        *(undefined *)(piVar10 + 4) = 0xe;
      }
    }
    break;
  case 0xd:
    if ((FLOAT_803e5314 < *(float *)(psVar2 + 0x4c)) && (*(float *)(psVar2 + 0x4c) < FLOAT_803e5320)
       ) {
      if (unaff_r26 < 0x401) {
        if (unaff_r26 < -0x400) {
          local_40 = (double)(longlong)(int)(FLOAT_803e5324 * FLOAT_803dc074);
          *psVar2 = *psVar2 + (short)(int)(FLOAT_803e5324 * FLOAT_803dc074);
        }
        else {
          *psVar2 = unaff_r27;
        }
      }
      else {
        local_40 = (double)(longlong)(int)(FLOAT_803e5324 * FLOAT_803dc074);
        *psVar2 = *psVar2 - (short)(int)(FLOAT_803e5324 * FLOAT_803dc074);
      }
    }
    if ((*(byte *)((int)piVar10 + 0x11) & 1) != 0) {
      *(undefined *)(piVar10 + 4) = 0xc;
    }
    break;
  case 0xe:
    if (*piVar10 != 0) {
      if (*(int *)(psVar2 + 100) != 0) {
        dVar11 = (double)FUN_80037da8((int)psVar2,*piVar10);
      }
      FUN_8002cc9c(dVar11,param_2,param_3,param_4,param_5,param_6,param_7,param_8,*piVar10);
      *piVar10 = 0;
    }
    psVar2[3] = psVar2[3] | 0x4000;
    psVar2[0x58] = psVar2[0x58] | 0x8000;
    FUN_80035ff8((int)psVar2);
    goto LAB_801ab9cc;
  }
  if ((*(byte *)(piVar10 + 4) < 5) || (10 < *(byte *)(piVar10 + 4))) {
    pfVar7 = (float *)0x0;
    iVar8 = FUN_80036974((int)psVar2,&local_58,(int *)0x0,(uint *)0x0);
    if ((iVar8 != 0) &&
       ((*(short *)(local_58 + 0x46) == 0x11 || (*(short *)(local_58 + 0x46) == 0x33)))) {
      pfVar7 = (float *)0x0;
      in_r7 = (uint *)0x0;
      in_r8 = 1;
      FUN_8002ad08(psVar2,0xf,200,0,0,1);
    }
  }
  else {
    pfVar7 = local_54 + 2;
    iVar8 = FUN_80037b60((int)psVar2,(float *)&DAT_803de7b8,(undefined4 *)0x0,pfVar7);
    if (iVar8 != 0) {
      dVar11 = FUN_80021730((float *)(psVar2 + 0xc),(float *)(piVar10[1] + 0x18));
      if (dVar11 < (double)FLOAT_803e5328) {
        in_r7 = (uint *)0x78;
        FUN_80097228(local_54 + 2,8,0xff,0xff,0x78);
        pfVar7 = (float *)0x0;
        FUN_8009a468(psVar2,local_54 + 2,4,(int *)0x0);
      }
      FUN_8000bb38((uint)psVar2,0x129);
    }
  }
  uVar4 = (uint)(byte)(&DAT_80324058)[*(byte *)(piVar10 + 4)];
  if (uVar4 != (int)psVar2[0x50]) {
    if (((&DAT_80324048)[*(byte *)(piVar10 + 4)] & 2) == 0) {
      FUN_8003042c((double)FLOAT_803e5318,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                   psVar2,uVar4,0,pfVar7,in_r7,in_r8,in_r9,in_r10);
    }
    else {
      FUN_8003042c((double)FLOAT_803e5330,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                   psVar2,uVar4,0,pfVar7,in_r7,in_r8,in_r9,in_r10);
    }
  }
  iVar8 = FUN_8002fb40((double)*(float *)(&DAT_80324068 + (uint)*(byte *)(piVar10 + 4) * 4),
                       (double)FLOAT_803dc074);
  if (iVar8 == 0) {
    *(byte *)((int)piVar10 + 0x11) = *(byte *)((int)piVar10 + 0x11) & 0xfe;
  }
  else {
    *(byte *)((int)piVar10 + 0x11) = *(byte *)((int)piVar10 + 0x11) | 1;
  }
LAB_801ab9cc:
  FUN_80286880();
  return;
}

