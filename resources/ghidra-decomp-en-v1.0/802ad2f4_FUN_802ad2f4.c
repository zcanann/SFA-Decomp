// Function: FUN_802ad2f4
// Entry: 802ad2f4
// Size: 2324 bytes

/* WARNING: Removing unreachable block (ram,0x802adbe0) */

undefined4 FUN_802ad2f4(int param_1,int param_2,int param_3)

{
  float fVar1;
  short sVar2;
  float fVar3;
  undefined uVar4;
  undefined4 uVar5;
  int iVar6;
  undefined4 uVar7;
  undefined8 in_f31;
  double dVar8;
  float local_2c;
  float local_28;
  float local_24;
  undefined auStack8 [8];
  
  uVar7 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  *(float *)(param_1 + 0x28) = -(FLOAT_803e7efc * FLOAT_803db414 - *(float *)(param_1 + 0x28));
  fVar1 = FLOAT_803e7ea4;
  sVar2 = *(short *)(param_1 + 0xa0);
  if (sVar2 == 0x13) {
    *(float *)(param_3 + 0x284) = FLOAT_803e7ea4;
    *(float *)(param_1 + 0x28) = fVar1;
    if (*(float *)(param_1 + 0x98) < FLOAT_803e7f10 * *(float *)(param_3 + 0x2a0)) {
      if ((1 < *(byte *)(param_2 + 0x3f7)) && ((*(byte *)(param_2 + 0x3f2) >> 2 & 1) == 0)) {
        FUN_8000fad8();
        FUN_8000e67c((double)FLOAT_803e7ed8);
        FUN_8003842c(param_1,0xb,&local_2c,&local_28,&local_24,0);
        if (*(char *)(param_2 + 0x86c) == '\x1a') {
          uVar4 = 0x14;
        }
        else {
          uVar4 = 2;
        }
        FUN_800365b8((double)local_2c,(double)local_28,(double)local_24,param_1,0,uVar4,1,0);
        *(byte *)(param_2 + 0x3f2) = *(byte *)(param_2 + 0x3f2) & 0xfb | 4;
      }
    }
    else {
      *(byte *)(param_2 + 0x3f2) = *(byte *)(param_2 + 0x3f2) & 0xf7;
    }
    if (*(char *)(param_3 + 0x346) != '\0') {
      *(byte *)(param_2 + 0x3f0) = *(byte *)(param_2 + 0x3f0) & 0xfb;
      *(byte *)(param_2 + 0x3f3) = *(byte *)(param_2 + 0x3f3) & 0xbf | 0x40;
      *(undefined *)(param_2 + 0x40d) = 0;
      uVar5 = 1;
      goto LAB_802adbe0;
    }
    if (*(byte *)(param_2 + 0x3f7) < 2) {
      *(undefined *)(param_2 + 0x8c5) = 3;
    }
    else {
      *(undefined *)(param_2 + 0x8c5) = 4;
    }
  }
  else if (sVar2 < 0x13) {
    if (sVar2 == 0xb) {
      *(float *)(param_3 + 0x284) = FLOAT_803e7ea4;
      if (*(char *)(param_3 + 0x346) != '\0') {
        if (**(char **)(param_2 + 0x35c) < '\x01') {
          *(byte *)(param_2 + 0x3f0) = *(byte *)(param_2 + 0x3f0) & 0xfb;
          *(undefined *)(param_2 + 0x40d) = 0;
          FUN_802aaa80();
        }
        else {
          FUN_80030334(param_1,0xc,0);
          *(float *)(param_3 + 0x2a0) = FLOAT_803e8038;
        }
      }
      (**(code **)(*DAT_803dca8c + 0x20))((double)FLOAT_803db414,param_1,param_3,2);
      *(undefined *)(param_2 + 0x8c5) = 4;
    }
    else {
      if (sVar2 < 0xb) {
        if (9 < sVar2) goto LAB_802ad384;
      }
      else if (sVar2 < 0xd) {
        if (((*(uint *)(param_3 + 0x314) & 1) != 0) && (*(short *)(param_2 + 0x81a) != 0)) {
          FUN_8000bb18(param_1,0x20e);
          FUN_8000bb18(param_1,0x20f);
        }
        if (*(char *)(param_3 + 0x346) != '\0') {
          *(byte *)(param_2 + 0x3f0) = *(byte *)(param_2 + 0x3f0) & 0xfb;
          *(byte *)(param_2 + 0x3f3) = *(byte *)(param_2 + 0x3f3) & 0xbf | 0x40;
          *(undefined *)(param_2 + 0x40d) = 0;
          uVar5 = 1;
          goto LAB_802adbe0;
        }
        (**(code **)(*DAT_803dca8c + 0x20))((double)FLOAT_803db414,param_1,param_3,2);
        *(undefined *)(param_2 + 0x8c5) = 4;
        goto LAB_802ad654;
      }
LAB_802ad5e4:
      FUN_80030334((double)FLOAT_803e7ea4,param_1,0x54,0);
      FUN_8002f574(param_1,0x14);
      *(float *)(param_3 + 0x2a0) = FLOAT_803e7f6c;
      *(undefined *)(param_2 + 0x8c5) = 2;
      *(undefined *)(param_2 + 0x3f7) = 0;
      *(byte *)(param_2 + 0x3f0) = *(byte *)(param_2 + 0x3f0) & 0xfe;
      *(byte *)(param_2 + 0x3f2) = *(byte *)(param_2 + 0x3f2) & 0xf7;
      *(byte *)(param_2 + 0x3f2) = *(byte *)(param_2 + 0x3f2) & 0xfb;
      *(byte *)(param_2 + 0x3f2) = *(byte *)(param_2 + 0x3f2) & 0xfd;
      *(undefined4 *)(param_2 + 0x848) = *(undefined4 *)(param_1 + 0x1c);
    }
  }
  else {
    if ((sVar2 != 0x90) && ((0x8f < sVar2 || (sVar2 != 0x54)))) goto LAB_802ad5e4;
LAB_802ad384:
    *(undefined *)(param_2 + 0x8c5) = 2;
  }
LAB_802ad654:
  dVar8 = (double)(*(float *)(param_2 + 0x848) - *(float *)(param_1 + 0x1c));
  if (((*(byte *)(param_2 + 0x3f1) & 1) != 0) && ((*(byte *)(param_2 + 0x3f0) & 1) == 0)) {
    *(byte *)(param_2 + 0x3f0) = *(byte *)(param_2 + 0x3f0) & 0xfe | 1;
    uVar5 = FUN_8006ed24(*(undefined *)(param_2 + 0x86c),*(undefined *)(param_2 + 0x8a5));
    if (dVar8 <= (double)FLOAT_803e8104) {
      if (dVar8 <= (double)FLOAT_803e8108) {
        if (dVar8 <= (double)FLOAT_803e810c) {
          FUN_80014aa0((double)FLOAT_803e7f10);
          FUN_8000bb18(0,uVar5);
          *(byte *)(param_2 + 0x3f0) = *(byte *)(param_2 + 0x3f0) & 0xfb;
          *(undefined *)(param_2 + 0x40d) = 0;
          *(byte *)(param_2 + 0x3f1) = *(byte *)(param_2 + 0x3f1) & 0xf7 | 8;
          *(byte *)(param_2 + 0x3f2) = *(byte *)(param_2 + 0x3f2) & 0xef | 0x10;
          *(byte *)(param_2 + 0x3f2) = *(byte *)(param_2 + 0x3f2) & 0xf7 | 8;
          if (FLOAT_803e7fc4 < *(float *)(param_2 + 0x838)) {
            FUN_8000bb18(param_1,0x42b);
          }
        }
        else {
          FUN_80014aa0((double)FLOAT_803e7ed8);
          FUN_80030334((double)FLOAT_803e7ea4,param_1,0x13,0);
          *(float *)(param_3 + 0x2a0) = FLOAT_803e800c;
          FUN_8000bb18(param_1,uVar5);
          if (*(short *)(param_2 + 0x81a) == 0) {
            uVar5 = 0x399;
          }
          else {
            uVar5 = 0x27;
          }
          FUN_8000bb18(param_1,uVar5);
          *(byte *)(param_2 + 0x3f2) = *(byte *)(param_2 + 0x3f2) & 0xf7 | 8;
          if (FLOAT_803e7fc4 < *(float *)(param_2 + 0x838)) {
            FUN_8000bb18(param_1,0x42a);
          }
        }
      }
      else {
        FUN_80014aa0((double)FLOAT_803e7ed8);
        FUN_80030334((double)FLOAT_803e7ea4,param_1,0x13,0);
        *(float *)(param_3 + 0x2a0) = FLOAT_803e800c;
        FUN_8000bb18(param_1,uVar5);
        if (*(short *)(param_2 + 0x81a) == 0) {
          uVar5 = 0x2d0;
        }
        else {
          uVar5 = 0x26;
        }
        FUN_8000b824(param_1,uVar5);
        *(byte *)(param_2 + 0x3f2) = *(byte *)(param_2 + 0x3f2) & 0xf7 | 8;
        if (FLOAT_803e7fc4 < *(float *)(param_2 + 0x838)) {
          FUN_8000bb18(param_1,0x429);
        }
      }
    }
    else {
      FUN_80014aa0((double)FLOAT_803e7fa4);
      FUN_8000fad8();
      FUN_8000e67c((double)FLOAT_803e7f58);
      FUN_80030334((double)FLOAT_803e7ea4,param_1,0xb,0);
      *(float *)(param_3 + 0x2a0) = FLOAT_803e7f34;
      FUN_8000bb18(param_1,0x20d);
      FUN_8000bb18(param_1,0x28);
      FUN_8003842c(param_1,0xb,&local_2c,&local_28,&local_24,0);
      if (*(char *)(param_2 + 0x86c) == '\x1a') {
        uVar4 = 0x14;
      }
      else {
        uVar4 = 2;
      }
      FUN_800365b8((double)local_2c,(double)local_28,(double)local_24,param_1,0,uVar4,2,0);
      *(byte *)(param_2 + 0x3f2) = *(byte *)(param_2 + 0x3f2) & 0xf7;
      if (FLOAT_803e7fc4 < *(float *)(param_2 + 0x838)) {
        FUN_8000bb18(param_1,0x428);
      }
    }
    fVar1 = FLOAT_803e7ea4;
    if ((double)FLOAT_803e810c < dVar8) {
      *(float *)(param_3 + 0x294) = FLOAT_803e7ea4;
      *(float *)(param_3 + 0x280) = fVar1;
    }
    *(float *)(param_3 + 0x284) = FLOAT_803e7ea4;
  }
  if ((*(byte *)(param_2 + 0x3f0) & 1) == 0) {
    if (*(float *)(param_3 + 0x1b0) < FLOAT_803e80c4) {
      *(byte *)(param_2 + 0x3f2) = *(byte *)(param_2 + 0x3f2) & 0xf7 | 8;
    }
    if ((dVar8 <= (double)FLOAT_803e8104) || (2 < *(byte *)(param_2 + 0x3f7))) {
      if ((dVar8 <= (double)FLOAT_803e8108) || (1 < *(byte *)(param_2 + 0x3f7))) {
        if (((double)FLOAT_803e810c < dVar8) && (*(char *)(param_2 + 0x3f7) == '\0')) {
          FUN_80030334((double)FLOAT_803e7ea4,param_1,0x90,0);
          FUN_8002f574(param_1,0x19);
          *(float *)(param_3 + 0x2a0) = FLOAT_803e7efc;
          *(undefined *)(param_2 + 0x3f7) = 1;
        }
      }
      else {
        if (*(short *)(param_2 + 0x81a) == 0) {
          uVar5 = 0x2d0;
        }
        else {
          uVar5 = 0x26;
        }
        iVar6 = FUN_8000b5d0(0,uVar5);
        if (iVar6 == 0) {
          if (*(short *)(param_2 + 0x81a) == 0) {
            uVar5 = 0x2d0;
          }
          else {
            uVar5 = 0x26;
          }
          FUN_8000bb18(param_1,uVar5);
        }
        *(undefined *)(param_2 + 0x3f7) = 2;
      }
    }
    else {
      FUN_80030334((double)FLOAT_803e7ea4,param_1,10,0);
      FUN_8002f574(param_1,0x19);
      *(float *)(param_3 + 0x2a0) = FLOAT_803e7ef8;
      *(undefined *)(param_2 + 0x3f7) = 3;
      *(byte *)(param_2 + 0x3f2) = *(byte *)(param_2 + 0x3f2) & 0xf7;
    }
  }
  if (((*(byte *)(param_2 + 0x3f2) >> 3 & 1) != 0) && ((*(ushort *)(param_2 + 0x6e2) & 0x400) != 0))
  {
    *(byte *)(param_2 + 0x3f2) = *(byte *)(param_2 + 0x3f2) & 0xfd | 2;
    *(ushort *)(param_2 + 0x6e2) = *(ushort *)(param_2 + 0x6e2) & 0xfbff;
  }
  if ((((*(byte *)(param_2 + 0x3f0) & 1) != 0) && ((*(byte *)(param_2 + 0x3f2) >> 1 & 1) != 0)) &&
     (*(byte *)(param_2 + 0x3f7) < 3)) {
    FUN_802aed2c(param_1,param_2,param_3);
    *(byte *)(param_2 + 0x3f0) = *(byte *)(param_2 + 0x3f0) & 0xfb;
    *(undefined *)(param_2 + 0x40d) = 0;
  }
  fVar1 = FLOAT_803e7fbc;
  if ((*(char *)(param_2 + 0x3f7) == '\0') && ((*(byte *)(param_2 + 0x3f4) >> 4 & 1) == 0)) {
    *(float *)(param_2 + 0x428) = FLOAT_803e7fbc;
    fVar3 = FLOAT_803e7e98;
    *(float *)(param_2 + 0x42c) = FLOAT_803e7e98;
    *(float *)(param_2 + 0x430) = fVar1;
    *(float *)(param_2 + 0x434) = fVar3;
    fVar1 = FLOAT_803e7f14;
    *(float *)(param_2 + 0x82c) = FLOAT_803e7f14;
    *(float *)(param_2 + 0x408) = *(float *)(param_2 + 0x408) * fVar1;
  }
  else {
    *(float *)(param_2 + 0x428) = FLOAT_803e7fbc;
    fVar3 = FLOAT_803e7ea4;
    *(float *)(param_2 + 0x42c) = FLOAT_803e7ea4;
    *(float *)(param_2 + 0x430) = fVar1;
    *(float *)(param_2 + 0x434) = fVar3;
    *(float *)(param_2 + 0x82c) = fVar3;
    *(float *)(param_2 + 0x408) = *(float *)(param_2 + 0x408) * fVar3;
  }
  fVar1 = *(float *)(param_2 + 0x408);
  fVar3 = FLOAT_803e8110;
  if ((FLOAT_803e8110 <= fVar1) && (fVar3 = fVar1, *(float *)(param_2 + 0x404) < fVar1)) {
    fVar3 = *(float *)(param_2 + 0x404);
  }
  *(float *)(param_2 + 0x408) = fVar3;
  if (*(char *)(param_2 + 0x8c8) == 'K') {
    (**(code **)(*DAT_803dca50 + 0x1c))(0x42,0,1,0,0,0,0xff);
    *(undefined *)(param_2 + 0x8c8) = 0x42;
  }
  uVar5 = 0;
LAB_802adbe0:
  __psq_l0(auStack8,uVar7);
  __psq_l1(auStack8,uVar7);
  return uVar5;
}

