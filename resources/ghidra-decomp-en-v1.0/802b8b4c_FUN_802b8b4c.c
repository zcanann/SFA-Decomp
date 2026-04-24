// Function: FUN_802b8b4c
// Entry: 802b8b4c
// Size: 1428 bytes

void FUN_802b8b4c(void)

{
  float fVar1;
  uint uVar2;
  int iVar3;
  undefined4 uVar4;
  int iVar5;
  char cVar6;
  int iVar7;
  int iVar8;
  int iVar9;
  double dVar10;
  float local_48;
  float local_44;
  float local_40;
  undefined auStack60 [12];
  float local_30;
  float local_2c;
  float local_28;
  
  iVar3 = FUN_802860dc();
  fVar1 = FLOAT_803e8180;
  iVar9 = *(int *)(iVar3 + 0xb8);
  iVar8 = *(int *)(iVar3 + 0x4c);
  iVar7 = *(int *)(iVar9 + 0x40c);
  if ((*(float *)(iVar7 + 0x10) != FLOAT_803e8180) &&
     (*(float *)(iVar7 + 0x10) = *(float *)(iVar7 + 0x10) - FLOAT_803db414,
     *(float *)(iVar7 + 0x10) <= fVar1)) {
    FUN_8002cbc4();
  }
  if ((*(short *)(iVar3 + 0x46) != 0x27c) || (*(short *)(iVar9 + 0x3f2) == -1)) goto LAB_802b8ec4;
  iVar5 = *(int *)(iVar8 + 0x14);
  if (iVar5 == 0x499ad) {
LAB_802b8e74:
    uVar4 = FUN_8001ffb4();
    uVar2 = countLeadingZeros(uVar4);
    *(uint *)(iVar3 + 0xf4) = uVar2 >> 5;
  }
  else {
    if (0x499ac < iVar5) {
      if (iVar5 < 0x499b3) {
        if (iVar5 < 0x499b0) goto LAB_802b8c44;
        iVar5 = FUN_8001ffb4(0xc46);
        if ((iVar5 == 0) || (iVar5 = FUN_8001ffb4((int)*(short *)(iVar9 + 0x3f2)), iVar5 != 0)) {
          *(undefined4 *)(iVar3 + 0xf4) = 1;
        }
        else {
          iVar5 = FUN_8002e0b4(0x499b6);
          if ((iVar5 != 0) &&
             (dVar10 = (double)FUN_80021704(iVar3 + 0x18,iVar5 + 0x18),
             dVar10 < (double)FLOAT_803e8214)) {
            FUN_800200e8((int)*(short *)(iVar9 + 0x3f2),1);
            local_30 = FLOAT_803e8180;
            local_2c = FLOAT_803e8218;
            local_28 = FLOAT_803e8180;
            for (cVar6 = '\x14'; cVar6 != '\0'; cVar6 = cVar6 + -1) {
              FUN_800972dc((double)FLOAT_803e81d0,(double)FLOAT_803e8218,iVar3,5,5,6,100,auStack60,0
                          );
            }
            iVar5 = FUN_8001ffb4(0xc3e);
            if (((iVar5 == 0) || (iVar5 = FUN_8001ffb4(0xc3f), iVar5 == 0)) ||
               (iVar5 = FUN_8001ffb4(0xc40), iVar5 == 0)) {
              FUN_8000bb18(0,0x409);
            }
            else {
              FUN_8000bb18(0,0x7e);
            }
          }
          uVar4 = FUN_8001ffb4((int)*(short *)(iVar9 + 0x3f2));
          *(undefined4 *)(iVar3 + 0xf4) = uVar4;
        }
        goto LAB_802b8e84;
      }
      goto LAB_802b8e74;
    }
    if (iVar5 < 0x49942) {
      if (iVar5 < 0x4993f) goto LAB_802b8e74;
      iVar5 = FUN_8001ffb4(0xc44);
      if (iVar5 == 0) {
        *(undefined4 *)(iVar3 + 0xf4) = 1;
      }
      else {
        uVar4 = FUN_8001ffb4((int)*(short *)(iVar9 + 0x3f2));
        *(undefined4 *)(iVar3 + 0xf4) = uVar4;
      }
    }
    else {
      if (iVar5 < 0x499ac) goto LAB_802b8e74;
LAB_802b8c44:
      iVar5 = FUN_8001ffb4(0xc42);
      if ((iVar5 == 0) || (iVar5 = FUN_8001ffb4((int)*(short *)(iVar9 + 0x3f2)), iVar5 != 0)) {
        *(undefined4 *)(iVar3 + 0xf4) = 1;
      }
      else {
        iVar5 = FUN_8002e0b4(0x499b5);
        if ((iVar5 != 0) &&
           (dVar10 = (double)FUN_80021704(iVar3 + 0x18,iVar5 + 0x18),
           dVar10 < (double)FLOAT_803e8214)) {
          FUN_800200e8((int)*(short *)(iVar9 + 0x3f2),1);
          local_30 = FLOAT_803e8180;
          local_2c = FLOAT_803e8218;
          local_28 = FLOAT_803e8180;
          for (cVar6 = '\x14'; cVar6 != '\0'; cVar6 = cVar6 + -1) {
            FUN_800972dc((double)FLOAT_803e81d0,(double)FLOAT_803e8218,iVar3,5,5,6,100,auStack60,0);
          }
          iVar5 = FUN_8001ffb4(0xc3b);
          if (((iVar5 == 0) || (iVar5 = FUN_8001ffb4(0xc3c), iVar5 == 0)) ||
             (iVar5 = FUN_8001ffb4(0xc3d), iVar5 == 0)) {
            FUN_8000bb18(0,0x409);
          }
          else {
            FUN_8000bb18(0,0x7e);
          }
        }
        uVar4 = FUN_8001ffb4((int)*(short *)(iVar9 + 0x3f2));
        *(undefined4 *)(iVar3 + 0xf4) = uVar4;
      }
    }
  }
LAB_802b8e84:
  if (*(int *)(iVar3 + 0xf4) == 0) {
    FUN_80035f20(iVar3);
    *(ushort *)(iVar3 + 6) = *(ushort *)(iVar3 + 6) & 0xbfff;
  }
  else {
    FUN_80035f00(iVar3);
    *(ushort *)(iVar3 + 6) = *(ushort *)(iVar3 + 6) | 0x4000;
  }
LAB_802b8ec4:
  if (*(int *)(iVar3 + 0xf4) == 0) {
    FUN_802b85e4(iVar3,iVar9);
    if ((*(ushort *)(iVar9 + 0x400) & 2) != 0) {
      FUN_802b827c(iVar3,iVar9,iVar7);
      FUN_802b84d0(iVar3);
      *(undefined4 *)(iVar3 + 0xf8) = 0;
      *(ushort *)(iVar9 + 0x400) = *(ushort *)(iVar9 + 0x400) & 0xfffd;
    }
    FUN_802b86b8(iVar3,iVar9,iVar9);
    if (((*(byte *)(iVar9 + 0x404) & 1) != 0) && ((*(ushort *)(iVar3 + 0xb0) & 0x800) != 0)) {
      iVar8 = *(int *)(iVar9 + 0x40c);
      *(float *)(iVar8 + 0xc) = *(float *)(iVar8 + 0xc) - FLOAT_803db414;
      if (FLOAT_803e8180 < *(float *)(iVar8 + 0xc)) {
        uVar4 = 0;
      }
      else {
        uVar4 = 3;
        *(float *)(iVar8 + 0xc) = *(float *)(iVar8 + 0xc) + FLOAT_803e81c0;
      }
      local_48 = FLOAT_803e8180;
      local_44 = FLOAT_803e81c4;
      local_40 = FLOAT_803e8180;
      FUN_8000da58(iVar3,0x455);
      FUN_80098b18((double)(FLOAT_803e81c8 * *(float *)(iVar3 + 8)),iVar3,3,uVar4,0,&local_48);
    }
    *(float *)(iVar7 + 0x14) = *(float *)(iVar7 + 0x14) - FLOAT_803db414;
  }
  else if ((((*(int *)(iVar8 + 0x14) == 0x499b5) && (iVar7 = FUN_8001ffb4(0xc42), iVar7 != 0)) &&
           ((iVar7 = FUN_8001ffb4(0xc3b), iVar7 == 0 ||
            ((iVar7 = FUN_8001ffb4(0xc3c), iVar7 == 0 || (iVar7 = FUN_8001ffb4(0xc3d), iVar7 == 0)))
            ))) || ((*(int *)(iVar8 + 0x14) == 0x499b6 &&
                    ((iVar7 = FUN_8001ffb4(0xc46), iVar7 != 0 &&
                     (((iVar7 = FUN_8001ffb4(0xc3e), iVar7 == 0 ||
                       (iVar7 = FUN_8001ffb4(0xc3f), iVar7 == 0)) ||
                      (iVar7 = FUN_8001ffb4(0xc40), iVar7 == 0)))))))) {
    local_30 = FLOAT_803e8180;
    local_2c = FLOAT_803e821c;
    local_28 = FLOAT_803e8180;
    FUN_80097734((double)FLOAT_803e8220,(double)FLOAT_803e8214,(double)FLOAT_803e8214,
                 (double)FLOAT_803e8224,iVar3,5,1,6,0x32,auStack60,0);
  }
  FUN_80286128();
  return;
}

