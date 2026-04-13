// Function: FUN_8014568c
// Entry: 8014568c
// Size: 1328 bytes

void FUN_8014568c(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,int param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)

{
  byte bVar1;
  float fVar2;
  uint uVar3;
  bool bVar9;
  int *piVar4;
  int iVar5;
  uint uVar6;
  undefined2 *puVar7;
  int iVar8;
  int iVar10;
  int *piVar11;
  undefined8 extraout_f1;
  undefined8 uVar12;
  undefined8 extraout_f1_00;
  undefined auStack_98 [13];
  char local_8b;
  
  uVar3 = FUN_80286834();
  piVar11 = *(int **)(uVar3 + 0xb8);
  uVar12 = extraout_f1;
  if ((piVar11[0x15] & 0x200U) == 0) {
    FUN_80035ff8(uVar3);
    FUN_8000b7dc(uVar3,0x7f);
    if ((piVar11[0x15] & 0x800U) != 0) {
      piVar11[0x15] = piVar11[0x15] & 0xfffff7ff;
      piVar11[0x15] = piVar11[0x15] | 0x1000;
      iVar10 = 0;
      piVar4 = piVar11;
      do {
        FUN_801784f8(piVar4[0x1c0]);
        piVar4 = piVar4 + 1;
        iVar10 = iVar10 + 1;
      } while (iVar10 < 7);
      FUN_8000dbb0();
      iVar10 = *(int *)(uVar3 + 0xb8);
      if (((*(byte *)(iVar10 + 0x58) >> 6 & 1) == 0) &&
         (((0x2f < *(short *)(uVar3 + 0xa0) || (*(short *)(uVar3 + 0xa0) < 0x29)) &&
          (bVar9 = FUN_8000b598(uVar3,0x10), !bVar9)))) {
        param_14 = 0;
        FUN_800394f0(uVar3,iVar10 + 0x3a8,0x29d,0,0xffffffff,0);
      }
    }
    uVar12 = FUN_8000dbb0();
    piVar11[0x15] = piVar11[0x15] | 0x200;
    if ((*(ushort *)(param_11 + 0x6e) & 3) == 0) {
      piVar11[0x15] = piVar11[0x15] | 0x4000;
    }
    if ((*(byte *)((int)piVar11 + 0x82e) >> 5 & 1) == 0) {
      piVar4 = (int *)FUN_8002b660(uVar3);
      uVar12 = FUN_80027b7c(piVar4);
      *(byte *)((int)piVar11 + 0x82e) = *(byte *)((int)piVar11 + 0x82e) & 0xbf;
    }
  }
  if (((piVar11[0x15] & 0x4000U) != 0) && ((*(ushort *)(piVar11[9] + 0xb0) & 0x40) != 0)) {
    *(undefined *)(piVar11 + 2) = 1;
    *(undefined *)((int)piVar11 + 10) = 0;
    fVar2 = FLOAT_803e306c;
    piVar11[0x1c7] = (int)FLOAT_803e306c;
    piVar11[0x1c8] = (int)fVar2;
    piVar11[0x15] = piVar11[0x15] & 0xffffffef;
    piVar11[0x15] = piVar11[0x15] & 0xfffeffff;
    piVar11[0x15] = piVar11[0x15] & 0xfffdffff;
    piVar11[0x15] = piVar11[0x15] & 0xfffbffff;
    *(undefined *)((int)piVar11 + 0xd) = 0xff;
    *(undefined *)((int)piVar11 + 9) = 0;
    piVar11[4] = (int)fVar2;
    piVar11[5] = (int)fVar2;
  }
  for (iVar10 = 0; iVar10 < (int)(uint)*(byte *)(param_11 + 0x8b); iVar10 = iVar10 + 1) {
    bVar1 = *(byte *)(param_11 + iVar10 + 0x81);
    if (bVar1 == 3) {
      *(undefined *)*piVar11 = *(undefined *)((int)piVar11 + 0x82d);
    }
    else if (bVar1 < 3) {
      if (bVar1 == 1) {
        if ((piVar11[0x15] & 0x800U) == 0) {
          uVar6 = FUN_8002e144();
          if ((uVar6 & 0xff) != 0) {
            piVar11[0x15] = piVar11[0x15] | 0x800;
            iVar8 = 0;
            piVar4 = piVar11;
            do {
              puVar7 = FUN_8002becc(0x24,0x4f0);
              *(undefined *)(puVar7 + 2) = 2;
              *(undefined *)((int)puVar7 + 5) = 1;
              puVar7[0xd] = (short)iVar8;
              iVar5 = FUN_8002e088(uVar12,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                                   puVar7,5,*(undefined *)(uVar3 + 0xac),0xffffffff,
                                   *(uint **)(uVar3 + 0x30),param_14,param_15,param_16);
              piVar4[0x1c0] = iVar5;
              piVar4 = piVar4 + 1;
              iVar8 = iVar8 + 1;
              uVar12 = extraout_f1_00;
            } while (iVar8 < 7);
            FUN_8000bb38(uVar3,0x3db);
            uVar12 = FUN_8000dcdc(uVar3,0x3dc);
          }
        }
        else {
          piVar11[0x15] = piVar11[0x15] & 0xfffff7ff;
          piVar11[0x15] = piVar11[0x15] | 0x1000;
          iVar8 = 0;
          piVar4 = piVar11;
          do {
            FUN_801784f8(piVar4[0x1c0]);
            piVar4 = piVar4 + 1;
            iVar8 = iVar8 + 1;
          } while (iVar8 < 7);
          uVar12 = FUN_8000dbb0();
          iVar8 = *(int *)(uVar3 + 0xb8);
          if (((*(byte *)(iVar8 + 0x58) >> 6 & 1) == 0) &&
             (((0x2f < *(short *)(uVar3 + 0xa0) || (*(short *)(uVar3 + 0xa0) < 0x29)) &&
              (bVar9 = FUN_8000b598(uVar3,0x10), !bVar9)))) {
            param_14 = 0;
            uVar12 = FUN_800394f0(uVar3,iVar8 + 0x3a8,0x29d,0,0xffffffff,0);
          }
        }
      }
      else if (bVar1 != 0) {
        uVar12 = FUN_800201ac(0x186,1);
        uVar6 = FUN_80020078(0x186);
        if (((uVar6 != 0) && (piVar11[499] == 0)) && (uVar6 = FUN_8002e144(), (uVar6 & 0xff) != 0))
        {
          uVar12 = FUN_80059da8(auStack_98);
          if (local_8b == '\0') {
            puVar7 = FUN_8002becc(0x20,0x254);
          }
          else {
            puVar7 = FUN_8002becc(0x20,0x244);
          }
          iVar8 = FUN_8002e088(uVar12,param_2,param_3,param_4,param_5,param_6,param_7,param_8,puVar7
                               ,4,0xff,0xffffffff,*(uint **)(uVar3 + 0x30),param_14,param_15,
                               param_16);
          piVar11[499] = iVar8;
          uVar12 = FUN_80037e24(uVar3,piVar11[499],3);
        }
      }
    }
    else if (bVar1 == 0x2c) {
      *(uint *)(*(int *)(uVar3 + 100) + 0x30) = *(uint *)(*(int *)(uVar3 + 100) + 0x30) | 4;
    }
    else if ((bVar1 < 0x2c) && (0x2a < bVar1)) {
      *(uint *)(*(int *)(uVar3 + 100) + 0x30) = *(uint *)(*(int *)(uVar3 + 100) + 0x30) & 0xfffffffb
      ;
    }
  }
  uVar12 = FUN_80138d68(uVar12,param_2,param_3,param_4,param_5,param_6,param_7,param_8,uVar3,
                        (int)piVar11,piVar11 + 0x1ea);
  uVar12 = FUN_80138d68(uVar12,param_2,param_3,param_4,param_5,param_6,param_7,param_8,uVar3,
                        (int)piVar11,piVar11 + 0x1ec);
  FUN_80138d68(uVar12,param_2,param_3,param_4,param_5,param_6,param_7,param_8,uVar3,(int)piVar11,
               piVar11 + 0x1ee);
  FUN_80139104(uVar3,piVar11);
  FUN_80138ee8(uVar3,piVar11);
  FUN_8006f0b4((double)FLOAT_803e3078,(double)FLOAT_803e3078,uVar3,param_11 + 0xf0,1,
               (int)(piVar11 + 0x1f6),(int)(piVar11 + 0x3e));
  if ((piVar11[0x15] & 1U) != 0) {
    *(ushort *)(param_11 + 0x6e) = *(ushort *)(param_11 + 0x6e) & 0xffbf;
    FUN_8003b408(uVar3,(int)(piVar11 + 0xde));
    (**(code **)(*DAT_803dd6d4 + 0x78))(uVar3,param_11,1,0xf,0x1e,0,0);
  }
  FUN_80286880();
  return;
}

