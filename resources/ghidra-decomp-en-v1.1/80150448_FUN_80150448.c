// Function: FUN_80150448
// Entry: 80150448
// Size: 1000 bytes

void FUN_80150448(undefined8 param_1,double param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,uint param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)

{
  byte bVar1;
  float fVar2;
  float fVar3;
  int iVar4;
  short *psVar5;
  uint uVar6;
  int iVar7;
  undefined *puVar8;
  float *pfVar9;
  double dVar10;
  double dVar11;
  undefined8 uVar12;
  
  uVar12 = FUN_80286840();
  fVar3 = FLOAT_803e33d8;
  psVar5 = (short *)((ulonglong)uVar12 >> 0x20);
  iVar7 = (int)uVar12;
  puVar8 = (&PTR_DAT_8031fdc4)[(uint)*(byte *)(iVar7 + 0x33b) * 10];
  if (((*(uint *)(iVar7 + 0x2dc) & 0x4000) != 0) ||
     ((dVar10 = (double)*(float *)(iVar7 + 0x328), dVar10 != (double)FLOAT_803e33d8 &&
      (*(short *)(iVar7 + 0x338) != 0)))) goto LAB_80150818;
  bVar1 = *(byte *)(iVar7 + 0x2f1);
  uVar6 = bVar1 & 0x1f;
  if ((bVar1 & 0x10) != 0) {
    uVar6 = bVar1 & 0x17;
  }
  if (0x18 < uVar6) {
    uVar6 = 0;
  }
  fVar2 = FLOAT_803e33e0;
  if ((bVar1 & 0x20) != 0) {
    uVar6 = 0;
    fVar2 = FLOAT_803e33dc;
  }
  dVar11 = (double)fVar2;
  if (((param_11 & 0xff) != 0) &&
     ((((bVar1 != 0 ||
        (dVar10 = (double)*(float *)(iVar7 + 0x324), dVar10 != (double)FLOAT_803e33d8)) &&
       ((*(uint *)(iVar7 + 0x2dc) & 0x40) == 0)) && ((bVar1 & 0x20) == 0)))) {
    param_2 = (double)*(float *)(iVar7 + 0x324);
    dVar10 = (double)FLOAT_803e33d8;
    if (param_2 == dVar10) {
      iVar4 = (uint)*(byte *)(iVar7 + 0x33b) * 2;
      uVar6 = FUN_80022264((uint)(byte)(&DAT_8031feac)[iVar4],(uint)(byte)(&DAT_8031fead)[iVar4]);
      *(float *)(iVar7 + 0x324) =
           *(float *)(iVar7 + 0x334) +
           (float)((double)CONCAT44(0x43300000,uVar6 ^ 0x80000000) - DOUBLE_803e33f0);
      *(float *)(iVar7 + 0x334) = FLOAT_803e33d8;
      goto LAB_80150818;
    }
    *(float *)(iVar7 + 0x324) = (float)(param_2 - (double)FLOAT_803dc074);
    if (dVar10 < (double)*(float *)(iVar7 + 0x324)) goto LAB_80150818;
    *(float *)(iVar7 + 0x324) = fVar3;
  }
  if ((((((param_11 & 0xff) == 0) || (*(char *)(iVar7 + 0x2f1) == '\0')) ||
       (puVar8[uVar6 * 0xc + 8] == '\0')) && ((*(byte *)(iVar7 + 0x2f1) & 0x20) == 0)) ||
     ((*(byte *)(iVar7 + 0x33c) == uVar6 &&
      (dVar10 = (double)FLOAT_803e33d8, dVar10 != (double)*(float *)(iVar7 + 0x32c))))) {
    if (*(float *)(iVar7 + 0x32c) != FLOAT_803e33d8) {
      dVar10 = (double)*(float *)(*(int *)(iVar7 + 0x29c) + 0x14);
      FUN_8014d3f4(psVar5,iVar7,0xf,0);
      if (FLOAT_803e33e8 < *(float *)(iVar7 + 0x308)) {
        *(float *)(iVar7 + 0x308) = *(float *)(iVar7 + 0x308) - FLOAT_803e33ec;
      }
      if ((*(uint *)(iVar7 + 0x2dc) & 0x40000000) != 0) {
        iVar4 = (uint)*(byte *)(iVar7 + 0x33c) * 0xc;
        FUN_8014d504((double)*(float *)(puVar8 + iVar4),dVar10,dVar11,param_4,param_5,param_6,
                     param_7,param_8,(int)psVar5,iVar7,(uint)(byte)puVar8[iVar4 + 8],0,
                     *(uint *)(puVar8 + iVar4 + 4) & 0xff,param_14,param_15,param_16);
        FUN_800303fc((double)*(float *)(&DAT_8031e980 +
                                       (uint)(byte)puVar8[(uint)*(byte *)(iVar7 + 0x33c) * 0xc + 8]
                                       * 4),(int)psVar5);
      }
      *(float *)(iVar7 + 0x32c) = *(float *)(iVar7 + 0x32c) - FLOAT_803dc074;
      if (*(float *)(iVar7 + 0x32c) <= FLOAT_803e33d8) {
        *(float *)(iVar7 + 0x32c) = FLOAT_803e33d8;
        *(uint *)(iVar7 + 0x2dc) = *(uint *)(iVar7 + 0x2dc) & 0xffffffbf;
        *(uint *)(iVar7 + 0x2dc) = *(uint *)(iVar7 + 0x2dc) | 0x40000000;
        *(byte *)(iVar7 + 0x2f2) = *(byte *)(iVar7 + 0x2f2) & 0x7f;
        *(undefined *)(iVar7 + 0x33c) = 0;
      }
    }
  }
  else if (((*(uint *)(iVar7 + 0x2dc) & 0x800080) == 0) && ((*(byte *)(iVar7 + 0x2f1) & 0x20) == 0))
  {
    if ((*(uint *)(iVar7 + 0x2dc) & 0x40000000) != 0) {
      FUN_80151840(dVar10,param_2,dVar11,param_4,param_5,param_6,param_7,param_8,psVar5,iVar7);
    }
  }
  else {
    pfVar9 = (float *)(puVar8 + uVar6 * 0xc);
    fVar3 = FLOAT_803e33e4 * (float)(dVar11 * (double)*pfVar9);
    *(float *)(iVar7 + 0x330) = fVar3;
    *(float *)(iVar7 + 0x32c) = fVar3;
    *(uint *)(iVar7 + 0x2dc) = *(uint *)(iVar7 + 0x2dc) | 0x40;
    *(byte *)(iVar7 + 0x2f2) = *(byte *)(iVar7 + 0x2f2) | 0x80;
    *(undefined *)(iVar7 + 0x2f3) = 0;
    *(undefined *)(iVar7 + 0x2f4) = 0;
    FUN_8014d504((double)(float)(dVar11 * (double)*pfVar9),param_2,dVar11,param_4,param_5,param_6,
                 param_7,param_8,(int)psVar5,iVar7,(uint)*(byte *)(pfVar9 + 2),0,
                 (uint)pfVar9[1] & 0xff,param_14,param_15,param_16);
    FUN_800303fc((double)*(float *)(&DAT_8031e980 + (uint)*(byte *)(pfVar9 + 2) * 4),(int)psVar5);
    *(char *)(iVar7 + 0x33c) = (char)uVar6;
  }
LAB_80150818:
  FUN_8028688c();
  return;
}

