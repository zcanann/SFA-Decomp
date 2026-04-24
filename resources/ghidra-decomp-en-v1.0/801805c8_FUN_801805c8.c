// Function: FUN_801805c8
// Entry: 801805c8
// Size: 1764 bytes

void FUN_801805c8(void)

{
  float fVar1;
  float fVar2;
  short *psVar3;
  int iVar4;
  int iVar5;
  undefined uVar7;
  int iVar6;
  float **ppfVar8;
  uint uVar9;
  int iVar10;
  int iVar11;
  float *pfVar12;
  double dVar13;
  int local_48;
  float **local_44;
  short local_40;
  undefined2 local_3e;
  undefined2 local_3c;
  float local_38;
  float local_34;
  float local_30;
  float local_2c;
  double local_28;
  longlong local_20;
  
  psVar3 = (short *)FUN_802860dc();
  pfVar12 = *(float **)(psVar3 + 0x5c);
  iVar11 = *(int *)(psVar3 + 0x26);
  iVar4 = FUN_8002b9ec();
  while (iVar5 = FUN_800374ec(psVar3,&local_48,0,0), iVar5 != 0) {
    if (local_48 == 0x7000b) {
      FUN_8000bb18(psVar3,0x4e);
      (**(code **)(*DAT_803dca88 + 8))(psVar3,0x51a,0,1,0xffffffff,0);
      (**(code **)(*DAT_803dca88 + 8))(psVar3,0x51a,0,1,0xffffffff,0);
      (**(code **)(*DAT_803dca88 + 8))(psVar3,0x51a,0,1,0xffffffff,0);
      FUN_800200e8((int)*(short *)(pfVar12 + 3),1);
      iVar5 = (**(code **)(*DAT_803dcaac + 0x8c))();
      uVar9 = *(byte *)(iVar5 + 9) + 1;
      if (*(byte *)(iVar5 + 10) < uVar9) {
        uVar9 = (uint)*(byte *)(iVar5 + 10);
      }
      *(char *)(iVar5 + 9) = (char)uVar9;
      *(undefined *)(pfVar12 + 7) = 1;
    }
  }
  if ((*(char *)((int)pfVar12 + 0x1b) == '\0') || (*(char *)(pfVar12 + 7) == '\x01')) {
    if (*(char *)((int)pfVar12 + 0x1b) == '\0') {
      uVar7 = FUN_8001ffb4((int)*(short *)((int)pfVar12 + 0xe));
      *(undefined *)((int)pfVar12 + 0x1b) = uVar7;
      *(undefined2 *)(pfVar12 + 2) = 0;
    }
  }
  else {
    if (FLOAT_803e38b8 < *(float *)(psVar3 + 0x14)) {
      *(float *)(psVar3 + 0x14) = FLOAT_803e38bc * FLOAT_803db414 + *(float *)(psVar3 + 0x14);
    }
    *(undefined *)((int)pfVar12 + 0x1a) = 0;
    if (-1 < *(char *)((int)pfVar12 + 0x1e)) {
      iVar6 = FUN_80065e50((double)*(float *)(psVar3 + 6),(double)*(float *)(psVar3 + 8),
                           (double)*(float *)(psVar3 + 10),psVar3,&local_44,0,0);
      iVar5 = -1;
      iVar10 = 0;
      ppfVar8 = local_44;
      fVar1 = FLOAT_803e38c0;
      if (0 < iVar6) {
        do {
          fVar2 = **ppfVar8 - *(float *)(psVar3 + 8);
          if (fVar2 < FLOAT_803e38c4) {
            fVar2 = -fVar2;
          }
          if (fVar2 < fVar1) {
            iVar5 = iVar10;
            fVar1 = fVar2;
          }
          ppfVar8 = ppfVar8 + 1;
          iVar10 = iVar10 + 1;
          iVar6 = iVar6 + -1;
        } while (iVar6 != 0);
      }
      if (iVar5 != -1) {
        *(byte *)((int)pfVar12 + 0x1e) = *(byte *)((int)pfVar12 + 0x1e) & 0x7f | 0x80;
        pfVar12[1] = *local_44[iVar5];
        *(float *)(psVar3 + 0x14) = FLOAT_803e38c4;
      }
      if (-1 < *(char *)((int)pfVar12 + 0x1e)) {
        pfVar12[1] = *(float *)(iVar11 + 0xc);
        *(byte *)((int)pfVar12 + 0x1e) = *(byte *)((int)pfVar12 + 0x1e) & 0x7f | 0x80;
      }
    }
    if (*(float *)(psVar3 + 8) < pfVar12[1]) {
      *(float *)(psVar3 + 8) = pfVar12[1];
      *(float *)(psVar3 + 0x14) = FLOAT_803e38c4;
    }
    if ((*(short *)(pfVar12 + 2) == 0) && (*(short *)((int)pfVar12 + 10) == 0)) {
      iVar11 = FUN_8002fa48((double)*pfVar12,(double)FLOAT_803db414,psVar3,0);
      if ((iVar11 == 0) && (*(char *)((int)pfVar12 + 0x1a) == '\0')) {
        *(float *)(psVar3 + 6) = *(float *)(psVar3 + 0x12) * FLOAT_803db414 + *(float *)(psVar3 + 6)
        ;
        *(float *)(psVar3 + 10) =
             *(float *)(psVar3 + 0x16) * FLOAT_803db414 + *(float *)(psVar3 + 10);
      }
      else {
        FUN_8000bb18(psVar3,0x4c);
        (**(code **)(*DAT_803dca88 + 8))(psVar3,0x51f,0,2,0xffffffff,0);
        (**(code **)(*DAT_803dca88 + 8))(psVar3,0x51f,0,2,0xffffffff,0);
        uVar7 = FUN_800221a0(0,4);
        *(undefined *)(pfVar12 + 6) = uVar7;
        fVar1 = FLOAT_803e38c4;
        if (*(char *)((int)pfVar12 + 0x1d) == '\0') {
          *(float *)(psVar3 + 0x12) = FLOAT_803e38c4;
          *(float *)(psVar3 + 0x16) = fVar1;
        }
        else {
          *(float *)(psVar3 + 0x12) = FLOAT_803e38c8;
          local_34 = FLOAT_803e38c4;
          *(float *)(psVar3 + 0x16) = FLOAT_803e38c4;
          local_30 = local_34;
          local_2c = local_34;
          local_38 = FLOAT_803e38b0;
          local_3c = 0;
          local_3e = 0;
          local_40 = *psVar3;
          FUN_80021ac8(&local_40,psVar3 + 0x12);
        }
        if (*(char *)((int)pfVar12 + 0x19) != '\0') {
          *(undefined2 *)((int)pfVar12 + 10) = 0xfa;
        }
      }
      iVar11 = FUN_8003687c(psVar3,0,0,0);
      if (iVar11 == 0xe) {
        *(undefined *)((int)pfVar12 + 0x19) = 1;
        FUN_8000bb18(psVar3,0x4d);
      }
    }
    else {
      if (*(short *)(pfVar12 + 2) != 0) {
        local_28 = (double)(longlong)(int)FLOAT_803db414;
        *(short *)(pfVar12 + 2) = *(short *)(pfVar12 + 2) - (short)(int)FLOAT_803db414;
        if (*(short *)(pfVar12 + 2) < 1) {
          *(undefined2 *)(pfVar12 + 2) = 0;
        }
      }
      if (*(short *)((int)pfVar12 + 10) != 0) {
        local_28 = (double)(longlong)(int)FLOAT_803db414;
        *(short *)((int)pfVar12 + 10) = *(short *)((int)pfVar12 + 10) - (short)(int)FLOAT_803db414;
        if (*(short *)((int)pfVar12 + 10) < 1) {
          *(undefined2 *)((int)pfVar12 + 10) = 0;
          *(undefined *)((int)pfVar12 + 0x19) = 0;
        }
      }
    }
    if (*(char *)(pfVar12 + 6) == '\x04') {
      if (*(char *)((int)pfVar12 + 0x1a) != '\0') {
        *psVar3 = *psVar3 + -0x7fff;
        *(undefined *)(pfVar12 + 6) = 0;
      }
      local_28 = (double)CONCAT44(0x43300000,(int)*psVar3 ^ 0x80000000);
      iVar11 = (int)(FLOAT_803e38cc * FLOAT_803db414 + (float)(local_28 - DOUBLE_803e38d8));
      local_20 = (longlong)iVar11;
      *psVar3 = (short)iVar11;
    }
    fVar1 = *(float *)(iVar4 + 0x10) - *(float *)(psVar3 + 8);
    if (fVar1 < FLOAT_803e38c4) {
      fVar1 = -fVar1;
    }
    if (((fVar1 < FLOAT_803e38d0) &&
        (dVar13 = (double)FUN_80021690(iVar4 + 0x18,psVar3 + 0xc), dVar13 < (double)FLOAT_803e38d4))
       && (iVar11 = FUN_8029622c(iVar4), iVar11 != 0)) {
      iVar11 = FUN_8001ffb4(0xcc0);
      if (iVar11 == 0) {
        *(undefined2 *)(pfVar12 + 4) = 0xffff;
        FUN_80035f00(psVar3);
        FUN_800378c4(iVar4,0x7000a,psVar3,pfVar12 + 4);
        FUN_800200e8(0xcc0,1);
      }
      else {
        iVar4 = (**(code **)(*DAT_803dcaac + 0x8c))();
        if (*(byte *)(iVar4 + 9) < *(byte *)(iVar4 + 10)) {
          FUN_8000bb18(psVar3,0x4e);
          (**(code **)(*DAT_803dca88 + 8))(psVar3,0x51a,0,1,0xffffffff,0);
          (**(code **)(*DAT_803dca88 + 8))(psVar3,0x51a,0,1,0xffffffff,0);
          (**(code **)(*DAT_803dca88 + 8))(psVar3,0x51a,0,1,0xffffffff,0);
          FUN_800200e8((int)*(short *)(pfVar12 + 3),1);
          iVar4 = (**(code **)(*DAT_803dcaac + 0x8c))();
          uVar9 = *(byte *)(iVar4 + 9) + 1;
          if (*(byte *)(iVar4 + 10) < uVar9) {
            uVar9 = (uint)*(byte *)(iVar4 + 10);
          }
          *(char *)(iVar4 + 9) = (char)uVar9;
          *(undefined *)(pfVar12 + 7) = 1;
          *(undefined *)(psVar3 + 0x1b) = 1;
        }
      }
      if (*(int *)(psVar3 + 0x2a) != 0) {
        FUN_80035f00(psVar3);
      }
    }
    *(float *)(psVar3 + 8) = *(float *)(psVar3 + 8) + *(float *)(psVar3 + 0x14);
  }
  FUN_80286128();
  return;
}

