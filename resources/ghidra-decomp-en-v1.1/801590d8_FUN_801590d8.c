// Function: FUN_801590d8
// Entry: 801590d8
// Size: 1624 bytes

void FUN_801590d8(undefined8 param_1,undefined8 param_2,double param_3,double param_4,double param_5
                 ,undefined8 param_6,undefined8 param_7,undefined8 param_8)

{
  float fVar1;
  uint uVar2;
  int iVar3;
  ushort *puVar4;
  int iVar5;
  int iVar6;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  undefined *puVar7;
  undefined *puVar8;
  undefined *puVar9;
  undefined *puVar10;
  undefined *puVar11;
  float *pfVar12;
  double dVar13;
  undefined8 extraout_f1;
  double dVar14;
  undefined8 uVar15;
  
  uVar15 = FUN_80286834();
  puVar4 = (ushort *)((ulonglong)uVar15 >> 0x20);
  iVar6 = (int)uVar15;
  uVar2 = (uint)*(byte *)(iVar6 + 0x33b);
  pfVar12 = (float *)(&PTR_DAT_80320748)[uVar2 * 8];
  puVar11 = (&PTR_DAT_80320740)[uVar2 * 8];
  puVar10 = (&PTR_DAT_80320744)[uVar2 * 8];
  puVar9 = (&PTR_DAT_8032074c)[uVar2 * 8];
  puVar8 = (&PTR_DAT_8032073c)[uVar2 * 8];
  puVar7 = (&PTR_DAT_80320750)[uVar2 * 8];
  if ((*(int *)(iVar6 + 0x29c) != 0) && (*(short *)(*(int *)(iVar6 + 0x29c) + 0x44) == 1)) {
    FUN_8001ff54();
  }
  if ((*(uint *)(iVar6 + 0x2dc) & 0x80000000) != 0) {
    if (*(char *)(iVar6 + 0x33b) == '\0') {
      (**(code **)(*DAT_803dd6d0 + 0x24))(0,0x6c,0);
    }
    *(byte *)(iVar6 + 0x33d) = *(byte *)(iVar6 + 0x33d) | 0x10;
    *(undefined *)(iVar6 + 0x33a) = 0;
    if (puVar4[0x23] == 0x6a2) {
      FUN_8000bb38((uint)puVar4,0x4a9);
      if (*(int *)(puVar4 + 100) != 0) {
        FUN_80220104(*(int *)(puVar4 + 100));
      }
    }
  }
  fVar1 = FLOAT_803e3840;
  dVar14 = (double)*(float *)(iVar6 + 0x328);
  dVar13 = (double)FLOAT_803e3840;
  if (((dVar14 != dVar13) && (*(char *)(iVar6 + 0x33f) != '\0')) &&
     (*(float *)(iVar6 + 0x328) = (float)(dVar14 - (double)FLOAT_803dc074),
     (double)*(float *)(iVar6 + 0x328) <= dVar13)) {
    *(float *)(iVar6 + 0x328) = fVar1;
    *(uint *)(iVar6 + 0x2dc) = *(uint *)(iVar6 + 0x2dc) | 0x40000000;
    *(char *)(iVar6 + 0x33c) =
         (char)*(undefined4 *)(puVar9 + (uint)*(byte *)(iVar6 + 0x33f) * 0x10 + 0xc);
    *(byte *)(puVar4 + 0x72) = *(byte *)(iVar6 + 0x33c) & 1;
    *(undefined *)(iVar6 + 0x33f) = puVar9[(uint)*(byte *)(iVar6 + 0x33f) * 0x10 + 10];
  }
  iVar5 = FUN_8014c594(puVar4,1,0x28,&DAT_803ad108);
  uVar15 = extraout_f1;
  if (iVar5 < 1) {
    if ((*(uint *)(iVar6 + 0x2dc) & 0x40000000) != 0) {
      *(byte *)(iVar6 + 0x33d) = *(byte *)(iVar6 + 0x33d) & 0xcf;
      if ((puVar4[0x23] == 0x6a2) && (*(int *)(puVar4 + 100) != 0)) {
        FUN_80220104(*(int *)(puVar4 + 100));
      }
      if (*(byte *)(iVar6 + 0x33f) == 0) {
        iVar5 = (uint)*(byte *)(iVar6 + 0x33e) * 0xc;
        puVar9 = puVar8 + iVar5;
        if ((*(uint *)(iVar6 + 0x2dc) & *(uint *)(puVar9 + 4)) == 0) {
          iVar5 = (uint)*(ushort *)(iVar6 + 0x2a0) * 0xc;
          if ((byte)puVar10[iVar5 + 8] == 0) {
            uVar2 = FUN_80022264(1,(uint)(byte)puVar11[8]);
            iVar5 = (uVar2 & 0xff) * 0xc;
            uVar15 = FUN_8014d504((double)*(float *)(puVar11 + iVar5),dVar14,param_3,param_4,param_5
                                  ,param_6,param_7,param_8,(int)puVar4,iVar6,
                                  (uint)(byte)puVar11[iVar5 + 8],0,(uint)(byte)puVar11[iVar5 + 10],
                                  puVar9,in_r9,in_r10);
          }
          else {
            uVar15 = FUN_8014d504((double)*(float *)(puVar10 + iVar5),dVar14,param_3,param_4,param_5
                                  ,param_6,param_7,param_8,(int)puVar4,iVar6,
                                  (uint)(byte)puVar10[iVar5 + 8],0,(uint)(byte)puVar10[iVar5 + 10],
                                  puVar9,in_r9,in_r10);
          }
        }
        else {
          iVar3 = (uint)*(ushort *)(iVar6 + 0x2a0) * 0xc;
          if ((byte)puVar10[iVar3 + 8] == 0) {
            uVar15 = FUN_8014d504((double)*(float *)(puVar8 + iVar5),dVar14,param_3,param_4,param_5,
                                  param_6,param_7,param_8,(int)puVar4,iVar6,(uint)(byte)puVar9[8],0,
                                  (uint)(byte)puVar9[10],puVar9,in_r9,in_r10);
          }
          else {
            uVar15 = FUN_8014d504((double)*(float *)(puVar10 + iVar3),dVar14,param_3,param_4,param_5
                                  ,param_6,param_7,param_8,(int)puVar4,iVar6,
                                  (uint)(byte)puVar10[iVar3 + 8],0,(uint)(byte)puVar10[iVar3 + 10],
                                  puVar9,in_r9,in_r10);
          }
        }
        *(undefined *)(iVar6 + 0x33e) = puVar8[(uint)*(byte *)(iVar6 + 0x33e) * 0xc + 9];
      }
      else {
        iVar5 = (uint)*(byte *)(iVar6 + 0x33f) * 0x10;
        uVar15 = FUN_8014d504((double)*(float *)(puVar9 + iVar5),dVar14,param_3,param_4,param_5,
                              param_6,param_7,param_8,(int)puVar4,iVar6,
                              (uint)(byte)puVar9[iVar5 + 8],0,*(uint *)(puVar9 + iVar5 + 4) & 0xff,
                              in_r8,in_r9,in_r10);
        *(char *)(iVar6 + 0x33c) =
             (char)*(undefined4 *)(puVar9 + (uint)*(byte *)(iVar6 + 0x33f) * 0x10 + 0xc);
        *(byte *)(puVar4 + 0x72) = *(byte *)(iVar6 + 0x33c) & 1;
        *(undefined *)(iVar6 + 0x33f) = puVar9[(uint)*(byte *)(iVar6 + 0x33f) * 0x10 + 9];
      }
    }
  }
  else if (((*(byte *)(iVar6 + 0x33d) & 0x20) == 0) ||
          ((*(uint *)(iVar6 + 0x2dc) & 0x40000000) != 0)) {
    if (*(byte *)(iVar6 + 0x33f) == 0) {
      dVar14 = -(double)(*(float *)(puVar4 + 0x10) - *(float *)(DAT_803ad108 + 0x20));
      uVar2 = FUN_80021884();
      uVar2 = (uVar2 & 0xffff) - (uint)*puVar4;
      if (0x8000 < (int)uVar2) {
        uVar2 = uVar2 - 0xffff;
      }
      if ((int)uVar2 < -0x8000) {
        uVar2 = uVar2 + 0xffff;
      }
      uVar2 = (uVar2 & 0xffff) >> 0xd;
      if ((uVar2 == 0) || (6 < uVar2)) {
        uVar15 = FUN_8014d504((double)*pfVar12,dVar14,param_3,param_4,param_5,param_6,param_7,
                              param_8,(int)puVar4,iVar6,(uint)*(byte *)(pfVar12 + 2),0,
                              (uint)*(byte *)((int)pfVar12 + 10),in_r8,in_r9,in_r10);
      }
      else if ((uVar2 < 3) || (4 < uVar2)) {
        iVar5 = (uint)*(ushort *)(iVar6 + 0x2a0) * 0xc;
        if ((byte)puVar10[iVar5 + 8] == 0) {
          iVar5 = (uint)*(byte *)(iVar6 + 0x33e) * 0xc;
          uVar15 = FUN_8014d504((double)*(float *)(puVar8 + iVar5),dVar14,param_3,param_4,param_5,
                                param_6,param_7,param_8,(int)puVar4,iVar6,
                                (uint)(byte)puVar8[iVar5 + 8],0,(uint)(byte)puVar8[iVar5 + 10],in_r8
                                ,in_r9,in_r10);
          *(undefined *)(iVar6 + 0x33e) = puVar8[(uint)*(byte *)(iVar6 + 0x33e) * 0xc + 9];
        }
        else {
          uVar15 = FUN_8014d504((double)*(float *)(puVar10 + iVar5),dVar14,param_3,param_4,param_5,
                                param_6,param_7,param_8,(int)puVar4,iVar6,
                                (uint)(byte)puVar10[iVar5 + 8],0,(uint)(byte)puVar10[iVar5 + 10],
                                in_r8,in_r9,in_r10);
        }
      }
      else {
        uVar2 = FUN_80022264(1,(uint)(byte)puVar11[8]);
        iVar5 = (uVar2 & 0xff) * 0xc;
        uVar15 = FUN_8014d504((double)*(float *)(puVar11 + iVar5),dVar14,param_3,param_4,param_5,
                              param_6,param_7,param_8,(int)puVar4,iVar6,
                              (uint)(byte)puVar11[iVar5 + 8],0,(uint)(byte)puVar11[iVar5 + 10],in_r8
                              ,in_r9,in_r10);
      }
      *(byte *)(iVar6 + 0x33d) = *(byte *)(iVar6 + 0x33d) | 0x20;
      *(byte *)(iVar6 + 0x33d) = *(byte *)(iVar6 + 0x33d) & 0xef;
    }
    else {
      iVar5 = (uint)*(byte *)(iVar6 + 0x33f) * 0x10;
      uVar15 = FUN_8014d504((double)*(float *)(puVar9 + iVar5),dVar14,param_3,param_4,param_5,
                            param_6,param_7,param_8,(int)puVar4,iVar6,(uint)(byte)puVar9[iVar5 + 8],
                            0,*(uint *)(puVar9 + iVar5 + 4) & 0xff,in_r8,in_r9,in_r10);
      *(char *)(iVar6 + 0x33c) =
           (char)*(undefined4 *)(puVar9 + (uint)*(byte *)(iVar6 + 0x33f) * 0x10 + 0xc);
      *(byte *)(puVar4 + 0x72) = *(byte *)(iVar6 + 0x33c) & 1;
      *(undefined *)(iVar6 + 0x33f) = puVar9[(uint)*(byte *)(iVar6 + 0x33f) * 0x10 + 9];
    }
  }
  *(undefined *)(*(int *)(puVar4 + 0x2a) + 0x6e) = 0;
  *(undefined *)(*(int *)(puVar4 + 0x2a) + 0x6f) = 0;
  iVar5 = 1;
  uVar2 = (uint)(byte)puVar7[8];
  puVar8 = puVar7;
  do {
    if (uVar2 == 0) {
LAB_801596cc:
      if (((*(byte *)(iVar6 + 0x323) & 8) == 0) && ((*(byte *)(iVar6 + 0x33d) & 0x10) == 0)) {
        dVar14 = (double)*(float *)(*(int *)(iVar6 + 0x29c) + 0x14);
        uVar15 = FUN_8014d3f4((short *)puVar4,iVar6,0x1e,0);
      }
      FUN_80158188(uVar15,dVar14,param_3,param_4,param_5,param_6,param_7,param_8);
      FUN_80286880();
      return;
    }
    if (puVar4[0x50] == (ushort)(byte)puVar8[0x14]) {
      *(char *)(*(int *)(puVar4 + 0x2a) + 0x6e) = (char)*(undefined4 *)(puVar7 + iVar5 * 0xc + 4);
      *(undefined *)(*(int *)(puVar4 + 0x2a) + 0x6f) = puVar7[iVar5 * 0xc + 9];
      if (*(char *)(*(int *)(puVar4 + 0x2a) + 0x6e) == '\x1f') {
        *(uint *)(iVar6 + 0x2e8) = *(uint *)(iVar6 + 0x2e8) | 0x40;
      }
      else {
        *(uint *)(iVar6 + 0x2e8) = *(uint *)(iVar6 + 0x2e8) & 0xffffffbf;
      }
      goto LAB_801596cc;
    }
    iVar5 = iVar5 + 1;
    uVar2 = uVar2 - 1;
    puVar8 = puVar8 + 0xc;
  } while( true );
}

