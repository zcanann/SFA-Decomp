// Function: FUN_802ada54
// Entry: 802ada54
// Size: 2324 bytes

/* WARNING: Removing unreachable block (ram,0x802ae340) */
/* WARNING: Removing unreachable block (ram,0x802ada64) */

undefined4
FUN_802ada54(undefined8 param_1,undefined8 param_2,double param_3,undefined8 param_4,
            undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
            short *param_9,int param_10,int param_11,int param_12,undefined4 param_13,
            undefined4 param_14,undefined4 param_15,undefined4 param_16)

{
  float fVar1;
  float fVar2;
  char cVar4;
  short sVar3;
  ushort uVar5;
  bool bVar6;
  double dVar7;
  double dVar8;
  double dVar9;
  float local_2c;
  float local_28;
  float local_24;
  
  dVar8 = (double)FLOAT_803e8b94;
  *(float *)(param_9 + 0x14) =
       -(float)(dVar8 * (double)FLOAT_803dc074 - (double)*(float *)(param_9 + 0x14));
  fVar1 = FLOAT_803e8b3c;
  sVar3 = param_9[0x50];
  if (sVar3 == 0x13) {
    *(float *)(param_11 + 0x284) = FLOAT_803e8b3c;
    *(float *)(param_9 + 0x14) = fVar1;
    dVar8 = (double)*(float *)(param_9 + 0x4c);
    if (dVar8 < (double)(FLOAT_803e8ba8 * *(float *)(param_11 + 0x2a0))) {
      if ((1 < *(byte *)(param_10 + 0x3f7)) && ((*(byte *)(param_10 + 0x3f2) >> 2 & 1) == 0)) {
        FUN_8000faf8();
        FUN_8000e69c((double)FLOAT_803e8b70);
        param_14 = 0;
        FUN_80038524(param_9,0xb,&local_2c,&local_28,&local_24,0);
        if (*(char *)(param_10 + 0x86c) == '\x1a') {
          cVar4 = '\x14';
        }
        else {
          cVar4 = '\x02';
        }
        param_12 = 1;
        param_13 = 0;
        dVar8 = (double)local_28;
        param_3 = (double)local_24;
        FUN_800366b0((double)local_2c,dVar8,param_3,(int)param_9,0,cVar4,1,0);
        *(byte *)(param_10 + 0x3f2) = *(byte *)(param_10 + 0x3f2) & 0xfb | 4;
      }
    }
    else {
      *(byte *)(param_10 + 0x3f2) = *(byte *)(param_10 + 0x3f2) & 0xf7;
    }
    if (*(char *)(param_11 + 0x346) != '\0') {
      *(byte *)(param_10 + 0x3f0) = *(byte *)(param_10 + 0x3f0) & 0xfb;
      *(byte *)(param_10 + 0x3f3) = *(byte *)(param_10 + 0x3f3) & 0xbf | 0x40;
      *(undefined *)(param_10 + 0x40d) = 0;
      return 1;
    }
    if (*(byte *)(param_10 + 0x3f7) < 2) {
      *(undefined *)(param_10 + 0x8c5) = 3;
    }
    else {
      *(undefined *)(param_10 + 0x8c5) = 4;
    }
    goto LAB_802addb4;
  }
  if (sVar3 < 0x13) {
    if (sVar3 == 0xb) {
      dVar7 = (double)FLOAT_803e8b3c;
      *(float *)(param_11 + 0x284) = FLOAT_803e8b3c;
      if (*(char *)(param_11 + 0x346) != '\0') {
        if (**(char **)(param_10 + 0x35c) < '\x01') {
          *(byte *)(param_10 + 0x3f0) = *(byte *)(param_10 + 0x3f0) & 0xfb;
          *(undefined *)(param_10 + 0x40d) = 0;
          FUN_802ab1e0(dVar7,dVar8,param_3,param_4,param_5,param_6,param_7,param_8,(int)param_9);
        }
        else {
          FUN_8003042c(dVar7,dVar8,param_3,param_4,param_5,param_6,param_7,param_8,param_9,0xc,0,
                       param_12,param_13,param_14,param_15,param_16);
          *(float *)(param_11 + 0x2a0) = FLOAT_803e8cd0;
        }
      }
      param_12 = *DAT_803dd70c;
      (**(code **)(param_12 + 0x20))((double)FLOAT_803dc074,param_9,param_11,2);
      *(undefined *)(param_10 + 0x8c5) = 4;
      goto LAB_802addb4;
    }
    if (sVar3 < 0xb) {
      if (9 < sVar3) goto LAB_802adae4;
    }
    else if (sVar3 < 0xd) {
      if (((*(uint *)(param_11 + 0x314) & 1) != 0) && (*(short *)(param_10 + 0x81a) != 0)) {
        FUN_8000bb38((uint)param_9,0x20e);
        FUN_8000bb38((uint)param_9,0x20f);
      }
      if (*(char *)(param_11 + 0x346) != '\0') {
        *(byte *)(param_10 + 0x3f0) = *(byte *)(param_10 + 0x3f0) & 0xfb;
        *(byte *)(param_10 + 0x3f3) = *(byte *)(param_10 + 0x3f3) & 0xbf | 0x40;
        *(undefined *)(param_10 + 0x40d) = 0;
        return 1;
      }
      param_12 = *DAT_803dd70c;
      (**(code **)(param_12 + 0x20))((double)FLOAT_803dc074,param_9,param_11,2);
      *(undefined *)(param_10 + 0x8c5) = 4;
      goto LAB_802addb4;
    }
  }
  else if ((sVar3 == 0x90) || ((sVar3 < 0x90 && (sVar3 == 0x54)))) {
LAB_802adae4:
    *(undefined *)(param_10 + 0x8c5) = 2;
    goto LAB_802addb4;
  }
  FUN_8003042c((double)FLOAT_803e8b3c,dVar8,param_3,param_4,param_5,param_6,param_7,param_8,param_9,
               0x54,0,param_12,param_13,param_14,param_15,param_16);
  FUN_8002f66c((int)param_9,0x14);
  *(float *)(param_11 + 0x2a0) = FLOAT_803e8c04;
  *(undefined *)(param_10 + 0x8c5) = 2;
  *(undefined *)(param_10 + 0x3f7) = 0;
  *(byte *)(param_10 + 0x3f0) = *(byte *)(param_10 + 0x3f0) & 0xfe;
  *(byte *)(param_10 + 0x3f2) = *(byte *)(param_10 + 0x3f2) & 0xf7;
  *(byte *)(param_10 + 0x3f2) = *(byte *)(param_10 + 0x3f2) & 0xfb;
  *(byte *)(param_10 + 0x3f2) = *(byte *)(param_10 + 0x3f2) & 0xfd;
  *(undefined4 *)(param_10 + 0x848) = *(undefined4 *)(param_9 + 0xe);
LAB_802addb4:
  dVar7 = (double)*(float *)(param_10 + 0x848);
  dVar9 = (double)(float)(dVar7 - (double)*(float *)(param_9 + 0xe));
  if (((*(byte *)(param_10 + 0x3f1) & 1) != 0) && ((*(byte *)(param_10 + 0x3f0) & 1) == 0)) {
    *(byte *)(param_10 + 0x3f0) = *(byte *)(param_10 + 0x3f0) & 0xfe | 1;
    uVar5 = FUN_8006eea0((uint)*(byte *)(param_10 + 0x86c),*(undefined *)(param_10 + 0x8a5));
    if (dVar9 <= (double)FLOAT_803e8d9c) {
      if (dVar9 <= (double)FLOAT_803e8da0) {
        if (dVar9 <= (double)FLOAT_803e8da4) {
          FUN_80014acc((double)FLOAT_803e8ba8);
          FUN_8000bb38(0,uVar5);
          *(byte *)(param_10 + 0x3f0) = *(byte *)(param_10 + 0x3f0) & 0xfb;
          *(undefined *)(param_10 + 0x40d) = 0;
          *(byte *)(param_10 + 0x3f1) = *(byte *)(param_10 + 0x3f1) & 0xf7 | 8;
          *(byte *)(param_10 + 0x3f2) = *(byte *)(param_10 + 0x3f2) & 0xef | 0x10;
          *(byte *)(param_10 + 0x3f2) = *(byte *)(param_10 + 0x3f2) & 0xf7 | 8;
          dVar7 = (double)*(float *)(param_10 + 0x838);
          if ((double)FLOAT_803e8c5c < dVar7) {
            dVar7 = (double)FUN_8000bb38((uint)param_9,0x42b);
          }
        }
        else {
          FUN_80014acc((double)FLOAT_803e8b70);
          FUN_8003042c((double)FLOAT_803e8b3c,dVar8,param_3,param_4,param_5,param_6,param_7,param_8,
                       param_9,0x13,0,param_12,param_13,param_14,param_15,param_16);
          *(float *)(param_11 + 0x2a0) = FLOAT_803e8ca4;
          FUN_8000bb38((uint)param_9,uVar5);
          if (*(short *)(param_10 + 0x81a) == 0) {
            uVar5 = 0x399;
          }
          else {
            uVar5 = 0x27;
          }
          FUN_8000bb38((uint)param_9,uVar5);
          *(byte *)(param_10 + 0x3f2) = *(byte *)(param_10 + 0x3f2) & 0xf7 | 8;
          dVar7 = (double)*(float *)(param_10 + 0x838);
          if ((double)FLOAT_803e8c5c < dVar7) {
            dVar7 = (double)FUN_8000bb38((uint)param_9,0x42a);
          }
        }
      }
      else {
        FUN_80014acc((double)FLOAT_803e8b70);
        FUN_8003042c((double)FLOAT_803e8b3c,dVar8,param_3,param_4,param_5,param_6,param_7,param_8,
                     param_9,0x13,0,param_12,param_13,param_14,param_15,param_16);
        *(float *)(param_11 + 0x2a0) = FLOAT_803e8ca4;
        FUN_8000bb38((uint)param_9,uVar5);
        if (*(short *)(param_10 + 0x81a) == 0) {
          sVar3 = 0x2d0;
        }
        else {
          sVar3 = 0x26;
        }
        FUN_8000b844((int)param_9,sVar3);
        *(byte *)(param_10 + 0x3f2) = *(byte *)(param_10 + 0x3f2) & 0xf7 | 8;
        dVar7 = (double)*(float *)(param_10 + 0x838);
        if ((double)FLOAT_803e8c5c < dVar7) {
          dVar7 = (double)FUN_8000bb38((uint)param_9,0x429);
        }
      }
    }
    else {
      FUN_80014acc((double)FLOAT_803e8c3c);
      FUN_8000faf8();
      FUN_8000e69c((double)FLOAT_803e8bf0);
      FUN_8003042c((double)FLOAT_803e8b3c,dVar8,param_3,param_4,param_5,param_6,param_7,param_8,
                   param_9,0xb,0,param_12,param_13,param_14,param_15,param_16);
      *(float *)(param_11 + 0x2a0) = FLOAT_803e8bcc;
      FUN_8000bb38((uint)param_9,0x20d);
      FUN_8000bb38((uint)param_9,0x28);
      param_14 = 0;
      FUN_80038524(param_9,0xb,&local_2c,&local_28,&local_24,0);
      if (*(char *)(param_10 + 0x86c) == '\x1a') {
        cVar4 = '\x14';
      }
      else {
        cVar4 = '\x02';
      }
      param_12 = 2;
      param_13 = 0;
      dVar8 = (double)local_28;
      param_3 = (double)local_24;
      FUN_800366b0((double)local_2c,dVar8,param_3,(int)param_9,0,cVar4,2,0);
      *(byte *)(param_10 + 0x3f2) = *(byte *)(param_10 + 0x3f2) & 0xf7;
      dVar7 = (double)*(float *)(param_10 + 0x838);
      if ((double)FLOAT_803e8c5c < dVar7) {
        dVar7 = (double)FUN_8000bb38((uint)param_9,0x428);
      }
    }
    fVar1 = FLOAT_803e8b3c;
    if ((double)FLOAT_803e8da4 < dVar9) {
      *(float *)(param_11 + 0x294) = FLOAT_803e8b3c;
      *(float *)(param_11 + 0x280) = fVar1;
    }
    *(float *)(param_11 + 0x284) = FLOAT_803e8b3c;
  }
  if ((*(byte *)(param_10 + 0x3f0) & 1) == 0) {
    dVar7 = (double)*(float *)(param_11 + 0x1b0);
    if (dVar7 < (double)FLOAT_803e8d5c) {
      *(byte *)(param_10 + 0x3f2) = *(byte *)(param_10 + 0x3f2) & 0xf7 | 8;
    }
    if ((dVar9 <= (double)FLOAT_803e8d9c) || (2 < *(byte *)(param_10 + 0x3f7))) {
      if ((dVar9 <= (double)FLOAT_803e8da0) || (1 < *(byte *)(param_10 + 0x3f7))) {
        if (((double)FLOAT_803e8da4 < dVar9) && (*(char *)(param_10 + 0x3f7) == '\0')) {
          FUN_8003042c((double)FLOAT_803e8b3c,dVar8,param_3,param_4,param_5,param_6,param_7,param_8,
                       param_9,0x90,0,param_12,param_13,param_14,param_15,param_16);
          dVar7 = (double)FUN_8002f66c((int)param_9,0x19);
          *(float *)(param_11 + 0x2a0) = FLOAT_803e8b94;
          *(undefined *)(param_10 + 0x3f7) = 1;
        }
      }
      else {
        if (*(short *)(param_10 + 0x81a) == 0) {
          sVar3 = 0x2d0;
        }
        else {
          sVar3 = 0x26;
        }
        bVar6 = FUN_8000b5f0(0,sVar3);
        if (!bVar6) {
          if (*(short *)(param_10 + 0x81a) == 0) {
            uVar5 = 0x2d0;
          }
          else {
            uVar5 = 0x26;
          }
          dVar7 = (double)FUN_8000bb38((uint)param_9,uVar5);
        }
        *(undefined *)(param_10 + 0x3f7) = 2;
      }
    }
    else {
      FUN_8003042c((double)FLOAT_803e8b3c,dVar8,param_3,param_4,param_5,param_6,param_7,param_8,
                   param_9,10,0,param_12,param_13,param_14,param_15,param_16);
      dVar7 = (double)FUN_8002f66c((int)param_9,0x19);
      *(float *)(param_11 + 0x2a0) = FLOAT_803e8b90;
      *(undefined *)(param_10 + 0x3f7) = 3;
      *(byte *)(param_10 + 0x3f2) = *(byte *)(param_10 + 0x3f2) & 0xf7;
    }
  }
  if (((*(byte *)(param_10 + 0x3f2) >> 3 & 1) != 0) &&
     ((*(ushort *)(param_10 + 0x6e2) & 0x400) != 0)) {
    *(byte *)(param_10 + 0x3f2) = *(byte *)(param_10 + 0x3f2) & 0xfd | 2;
    *(ushort *)(param_10 + 0x6e2) = *(ushort *)(param_10 + 0x6e2) & 0xfbff;
  }
  if ((((*(byte *)(param_10 + 0x3f0) & 1) != 0) && ((*(byte *)(param_10 + 0x3f2) >> 1 & 1) != 0)) &&
     (*(byte *)(param_10 + 0x3f7) < 3)) {
    FUN_802af48c(dVar7,dVar8,param_3,param_4,param_5,param_6,param_7,param_8,param_9,param_10,
                 param_11,param_12,param_13,param_14,param_15,param_16);
    *(byte *)(param_10 + 0x3f0) = *(byte *)(param_10 + 0x3f0) & 0xfb;
    *(undefined *)(param_10 + 0x40d) = 0;
  }
  fVar1 = FLOAT_803e8c54;
  if ((*(char *)(param_10 + 0x3f7) == '\0') && ((*(byte *)(param_10 + 0x3f4) >> 4 & 1) == 0)) {
    *(float *)(param_10 + 0x428) = FLOAT_803e8c54;
    fVar2 = FLOAT_803e8b30;
    *(float *)(param_10 + 0x42c) = FLOAT_803e8b30;
    *(float *)(param_10 + 0x430) = fVar1;
    *(float *)(param_10 + 0x434) = fVar2;
    fVar1 = FLOAT_803e8bac;
    *(float *)(param_10 + 0x82c) = FLOAT_803e8bac;
    *(float *)(param_10 + 0x408) = *(float *)(param_10 + 0x408) * fVar1;
  }
  else {
    *(float *)(param_10 + 0x428) = FLOAT_803e8c54;
    fVar2 = FLOAT_803e8b3c;
    *(float *)(param_10 + 0x42c) = FLOAT_803e8b3c;
    *(float *)(param_10 + 0x430) = fVar1;
    *(float *)(param_10 + 0x434) = fVar2;
    *(float *)(param_10 + 0x82c) = fVar2;
    *(float *)(param_10 + 0x408) = *(float *)(param_10 + 0x408) * fVar2;
  }
  fVar1 = *(float *)(param_10 + 0x408);
  fVar2 = FLOAT_803e8da8;
  if ((FLOAT_803e8da8 <= fVar1) && (fVar2 = fVar1, *(float *)(param_10 + 0x404) < fVar1)) {
    fVar2 = *(float *)(param_10 + 0x404);
  }
  *(float *)(param_10 + 0x408) = fVar2;
  if (*(char *)(param_10 + 0x8c8) == 'K') {
    (**(code **)(*DAT_803dd6d0 + 0x1c))(0x42,0,1,0,0,0,0xff);
    *(undefined *)(param_10 + 0x8c8) = 0x42;
  }
  return 0;
}

