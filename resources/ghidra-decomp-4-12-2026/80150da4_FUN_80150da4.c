// Function: FUN_80150da4
// Entry: 80150da4
// Size: 1484 bytes

void FUN_80150da4(undefined8 param_1,undefined8 param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)

{
  float fVar1;
  int iVar2;
  ushort *puVar3;
  char cVar4;
  undefined4 *puVar5;
  uint uVar6;
  undefined4 in_r6;
  uint in_r7;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  undefined *puVar7;
  undefined *puVar8;
  undefined *puVar9;
  float *pfVar10;
  double dVar11;
  double extraout_f1;
  undefined8 extraout_f1_00;
  double dVar12;
  double dVar13;
  double dVar14;
  undefined8 uVar15;
  
  uVar15 = FUN_8028683c();
  puVar3 = (ushort *)((ulonglong)uVar15 >> 0x20);
  puVar5 = (undefined4 *)uVar15;
  pfVar10 = (float *)*puVar5;
  uVar6 = (uint)*(byte *)((int)puVar5 + 0x33b);
  puVar9 = (&PTR_DAT_8031fdc0)[uVar6 * 10];
  puVar8 = (&PTR_DAT_8031fdbc)[uVar6 * 10];
  puVar7 = (&PTR_DAT_8031fdd8)[uVar6 * 10];
  if ((uVar6 == 5) && ((puVar5[0xb7] & 0x800000) != 0)) {
    FUN_800201ac(0x1c8,1);
  }
  FUN_80150830((uint)puVar3,(int)puVar5);
  fVar1 = FLOAT_803e33d8;
  dVar12 = (double)(float)puVar5[0xca];
  dVar11 = (double)FLOAT_803e33d8;
  if (((dVar12 != dVar11) && (*(short *)(puVar5 + 0xce) != 0)) &&
     (puVar5[0xca] = (float)(dVar12 - (double)FLOAT_803dc074), (double)(float)puVar5[0xca] <= dVar11
     )) {
    puVar5[0xca] = fVar1;
    puVar5[0xb7] = puVar5[0xb7] | 0x40000000;
    *(ushort *)(puVar5 + 0xce) = (ushort)(byte)puVar7[(uint)*(ushort *)(puVar5 + 0xce) * 0x10 + 10];
  }
  cVar4 = FUN_80150448(dVar11,dVar12,param_3,param_4,param_5,param_6,param_7,param_8,puVar3,puVar5,0
                       ,in_r6,in_r7,in_r8,in_r9,in_r10);
  fVar1 = FLOAT_803e33d8;
  if (cVar4 == '\0') {
    dVar11 = extraout_f1;
    if (*(char *)((int)puVar5 + 0x33d) != '\0') {
      if ((puVar5[0xb7] & 0x40000000) != 0) {
        *(float *)(puVar3 + 0x16) = FLOAT_803e33d8;
        *(float *)(puVar3 + 0x14) = fVar1;
        *(float *)(puVar3 + 0x12) = fVar1;
        iVar2 = (uint)*(byte *)((int)puVar5 + 0x33d) * 0xc;
        in_r6 = 0;
        in_r7 = *(uint *)(puVar9 + iVar2 + 4) & 0xff;
        FUN_8014d504((double)*(float *)(puVar9 + iVar2),dVar12,param_3,param_4,param_5,param_6,
                     param_7,param_8,(int)puVar3,(int)puVar5,(uint)(byte)puVar9[iVar2 + 8],0,in_r7,
                     in_r8,in_r9,in_r10);
        dVar11 = (double)*(float *)(&DAT_8031e980 +
                                   (uint)(byte)puVar9[(uint)*(byte *)((int)puVar5 + 0x33d) * 0xc + 8
                                                     ] * 4);
        FUN_800303fc(dVar11,(int)puVar3);
        *(undefined *)((int)puVar5 + 0x33d) = puVar9[(uint)*(byte *)((int)puVar5 + 0x33d) * 0xc + 9]
        ;
        *(undefined *)((int)puVar5 + 0x33e) = 0;
      }
      if (*(char *)((int)puVar5 + 0x33e) == '\0') goto LAB_80151358;
    }
    if (((puVar5[0xb7] & 0x80000000) != 0) && (*(char *)((int)puVar5 + 0x33d) == '\0')) {
      FUN_8014c4dc(dVar11,dVar12,param_3,param_4,param_5,param_6,param_7,param_8,(int)puVar3);
    }
    if ((puVar5[0xb7] & 0x2000) == 0) {
      if ((*(char *)((int)puVar5 + 0x33d) == '\0') && ((puVar5[0xb7] & 0x40000000) != 0)) {
        uVar6 = FUN_80022264(1,(uint)(byte)puVar9[8]);
        if (*(ushort *)(puVar5 + 0xce) == 0) {
          iVar2 = (uVar6 & 0xff) * 0xc;
          if ((puVar3[0x50] != (ushort)(byte)puVar9[iVar2 + 8]) || ((byte)puVar9[iVar2 + 8] != 0)) {
            *(undefined *)((int)puVar5 + 0x2f2) = 0;
            *(undefined *)((int)puVar5 + 0x2f3) = 0;
            *(undefined *)(puVar5 + 0xbd) = 0;
            FUN_8014d504((double)*(float *)(puVar9 + iVar2),dVar12,param_3,param_4,param_5,param_6,
                         param_7,param_8,(int)puVar3,(int)puVar5,(uint)(byte)puVar9[iVar2 + 8],0,3,
                         in_r8,in_r9,in_r10);
            FUN_800303fc((double)*(float *)(&DAT_8031e980 + (uint)(byte)puVar9[iVar2 + 8] * 4),
                         (int)puVar3);
          }
        }
        else {
          *(char *)((int)puVar5 + 0x2f2) =
               (char)*(undefined4 *)(puVar7 + (uint)*(ushort *)(puVar5 + 0xce) * 0x10 + 0xc);
          iVar2 = (uint)*(ushort *)(puVar5 + 0xce) * 0x10;
          FUN_8014d504((double)*(float *)(puVar7 + iVar2),dVar12,param_3,param_4,param_5,param_6,
                       param_7,param_8,(int)puVar3,(int)puVar5,(uint)(byte)puVar7[iVar2 + 8],0,
                       *(uint *)(puVar7 + iVar2 + 4) & 0xff,in_r8,in_r9,in_r10);
          FUN_800303fc((double)*(float *)(&DAT_8031e980 +
                                         (uint)(byte)puVar7[(uint)*(ushort *)(puVar5 + 0xce) * 0x10
                                                            + 8] * 4),(int)puVar3);
          *(ushort *)(puVar5 + 0xce) =
               (ushort)(byte)puVar7[(uint)*(ushort *)(puVar5 + 0xce) * 0x10 + 9];
        }
      }
    }
    else {
      dVar12 = (double)(pfVar10[0x1a] - *(float *)(puVar3 + 6));
      dVar11 = FUN_80293900((double)(float)(dVar12 * dVar12 +
                                           (double)((pfVar10[0x1c] - *(float *)(puVar3 + 10)) *
                                                   (pfVar10[0x1c] - *(float *)(puVar3 + 10)))));
      if ((double)FLOAT_803e3410 < dVar11) {
        dVar11 = (double)FLOAT_803e3410;
      }
      puVar5[0xc4] = (float)((double)FLOAT_803e3410 - dVar11) * FLOAT_803e3414 * (float)puVar5[0xbf]
      ;
      if ((float)puVar5[0xc4] < FLOAT_803e3418) {
        puVar5[0xc4] = FLOAT_803e3418;
      }
      iVar2 = FUN_80010340((double)(float)puVar5[0xc4],pfVar10);
      if (((iVar2 != 0) || (pfVar10[4] != 0.0)) &&
         (cVar4 = (**(code **)(*DAT_803dd71c + 0x90))(pfVar10), cVar4 != '\0')) {
        FUN_8014c4dc(extraout_f1_00,dVar12,param_3,param_4,param_5,param_6,param_7,param_8,
                     (int)puVar3);
      }
      uVar6 = FUN_80021884();
      dVar11 = (double)(float)((double)CONCAT44(0x43300000,
                                                ((uVar6 & 0xffff) + 0x8000) - (uint)*puVar3 ^
                                                0x80000000) - DOUBLE_803e33f0);
      if ((double)FLOAT_803e3420 < dVar11) {
        dVar11 = (double)(float)((double)FLOAT_803e341c + dVar11);
      }
      if (dVar11 < (double)FLOAT_803e3428) {
        dVar11 = (double)(float)((double)FLOAT_803e3424 + dVar11);
      }
      dVar14 = (double)(((float)puVar5[0xbf] - (float)puVar5[0xc4]) / FLOAT_803e33e4);
      dVar13 = (double)FLOAT_803e33e0;
      dVar12 = dVar11;
      if (dVar11 < (double)FLOAT_803e33d8) {
        dVar12 = -dVar11;
      }
      puVar5[0xc2] = (float)(dVar14 * (double)(float)(dVar13 - (double)(float)(dVar12 / (double)
                                                  FLOAT_803e3424)));
      if ((float)puVar5[0xc2] < FLOAT_803e33ec) {
        puVar5[0xc2] = FLOAT_803e33ec;
      }
      if (((puVar5[0xb7] & 0x40000000) != 0) && (*(char *)((int)puVar5 + 0x33d) == '\0')) {
        if (*(ushort *)(puVar5 + 0xce) == 0) {
          if ((float)puVar5[0xc4] <= FLOAT_803e342c) {
            *(undefined *)((int)puVar5 + 0x2f2) = 0;
            *(undefined *)((int)puVar5 + 0x2f3) = 0;
            *(undefined *)(puVar5 + 0xbd) = 0;
            *(undefined *)((int)puVar5 + 0x323) = 1;
            puVar5[0xc2] = FLOAT_803e3434;
            FUN_8003042c((double)FLOAT_803e33d8,dVar13,dVar14,dVar11,param_5,param_6,param_7,param_8
                         ,puVar3,(uint)(byte)puVar8[8],0,in_r6,in_r7,in_r8,in_r9,in_r10);
            puVar5[0xc4] = FLOAT_803e33d8;
          }
          else {
            *(undefined *)((int)puVar5 + 0x2f2) = 0;
            *(undefined *)((int)puVar5 + 0x2f3) = 0;
            *(undefined *)(puVar5 + 0xbd) = 0;
            if ((float)puVar5[0xc4] <= FLOAT_803e3430) {
              *(undefined *)((int)puVar5 + 0x323) = 1;
              FUN_8003042c((double)FLOAT_803e33d8,dVar13,dVar14,dVar11,param_5,param_6,param_7,
                           param_8,puVar3,(uint)(byte)puVar8[0x14],0,in_r6,in_r7,in_r8,in_r9,in_r10)
              ;
            }
            else {
              *(undefined *)((int)puVar5 + 0x323) = 1;
              FUN_8003042c((double)FLOAT_803e33d8,dVar13,dVar14,dVar11,param_5,param_6,param_7,
                           param_8,puVar3,(uint)(byte)puVar8[0x20],0,in_r6,in_r7,in_r8,in_r9,in_r10)
              ;
            }
          }
        }
        else {
          iVar2 = (uint)*(ushort *)(puVar5 + 0xce) * 0x10;
          FUN_8014d504((double)*(float *)(puVar7 + iVar2),dVar13,dVar14,dVar11,param_5,param_6,
                       param_7,param_8,(int)puVar3,(int)puVar5,(uint)(byte)puVar7[iVar2 + 8],0,
                       *(uint *)(puVar7 + iVar2 + 4) & 0xff,in_r8,in_r9,in_r10);
          FUN_800303fc((double)*(float *)(&DAT_8031e980 +
                                         (uint)(byte)puVar7[(uint)*(ushort *)(puVar5 + 0xce) * 0x10
                                                            + 8] * 4),(int)puVar3);
          *(ushort *)(puVar5 + 0xce) =
               (ushort)(byte)puVar7[(uint)*(ushort *)(puVar5 + 0xce) * 0x10 + 9];
        }
      }
      FUN_8014d3f4((short *)puVar3,puVar5,0xf,0);
    }
  }
LAB_80151358:
  FUN_80286888();
  return;
}

