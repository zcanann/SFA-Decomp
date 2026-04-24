// Function: FUN_80145f10
// Entry: 80145f10
// Size: 1648 bytes

void FUN_80145f10(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)

{
  char cVar1;
  ushort uVar2;
  bool bVar3;
  bool bVar4;
  bool bVar5;
  int iVar6;
  uint uVar7;
  int iVar8;
  bool bVar11;
  undefined2 *puVar9;
  undefined4 uVar10;
  byte bVar12;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  int iVar13;
  double extraout_f1;
  double extraout_f1_00;
  double dVar14;
  char local_38 [4];
  char local_34 [4];
  undefined4 local_30 [12];
  
  iVar6 = FUN_80286834();
  iVar13 = *(int *)(iVar6 + 0xb8);
  bVar11 = false;
  bVar3 = false;
  bVar4 = false;
  bVar5 = false;
  local_30[0] = DAT_803e3058;
  dVar14 = extraout_f1;
  uVar7 = FUN_80020078(0x4e4);
  if (uVar7 != 0) {
    if ((*(uint *)(iVar13 + 0x54) & 0x10) != 0) {
      *(undefined *)(iVar13 + 0xb) = 0;
    }
    cVar1 = *(char *)(iVar13 + 8);
    if (((cVar1 == '\b') || (cVar1 == '\r')) ||
       ((cVar1 == '\x0e' && (*(char *)(iVar13 + 10) == '\x01')))) {
      bVar3 = true;
    }
    else {
      iVar8 = FUN_80139330();
      dVar14 = extraout_f1_00;
      if (iVar8 != 0) {
        bVar3 = true;
        bVar5 = true;
      }
    }
    if (*(char *)(iVar13 + 0xb) != '\0') {
      for (bVar12 = 0; bVar12 < *(byte *)(iVar13 + 0x798); bVar12 = bVar12 + 1) {
        iVar8 = iVar13 + (uint)bVar12 * 8;
        cVar1 = *(char *)(iVar8 + 0x74c);
        if (cVar1 == '\0') {
          if (*(short *)(*(int *)(iVar8 + 0x748) + 0x46) == 0x6a) {
            bVar4 = true;
          }
          bVar3 = true;
        }
        else if (cVar1 == '\x01') {
          bVar11 = true;
        }
      }
    }
    if (((*(uint *)(iVar13 + 0x54) & 0x10) == 0) && (uVar7 = FUN_80020078(0x3f8), uVar7 != 0)) {
      iVar8 = FUN_8002bac4();
      iVar8 = FUN_802969a0(iVar8);
      if ((iVar8 != 0) && (uVar7 = FUN_80020078(0xd00), uVar7 == 0)) {
        FUN_80296ba8(*(int *)(iVar13 + 4));
      }
    }
    FUN_80020078(0xdd);
    FUN_80020078(0x9e);
    FUN_80020078(0x245);
    *(undefined *)(iVar13 + 0xb) = 0;
    if ((bVar11) && ((*(uint *)(iVar13 + 0x54) & 0x200) == 0)) {
      *(float *)(iVar13 + 0x7b4) = FLOAT_803e3188;
      if ((*(int *)(iVar13 + 0x7b0) == 0) && (uVar7 = FUN_8002e144(), (uVar7 & 0xff) != 0)) {
        uVar7 = FUN_80022264(0,1);
        uVar2 = *(ushort *)((int)local_30 + uVar7 * 2);
        iVar8 = *(int *)(iVar6 + 0xb8);
        if (((*(byte *)(iVar8 + 0x58) >> 6 & 1) == 0) &&
           (((0x2f < *(short *)(iVar6 + 0xa0) || (*(short *)(iVar6 + 0xa0) < 0x29)) &&
            (bVar11 = FUN_8000b598(iVar6,0x10), !bVar11)))) {
          in_r8 = 0;
          dVar14 = (double)FUN_800394f0(iVar6,iVar8 + 0x3a8,uVar2,0x500,0xffffffff,0);
        }
        puVar9 = FUN_8002becc(0x20,0x17c);
        local_34[0] = -1;
        local_34[1] = -1;
        local_34[2] = -1;
        if (*(int *)(iVar13 + 0x7a8) != 0) {
          local_34[*(byte *)(iVar13 + 0x7bc) >> 6] = '\x01';
        }
        if (*(int *)(iVar13 + 0x7b0) != 0) {
          local_34[*(byte *)(iVar13 + 0x7bc) >> 4 & 3] = '\x01';
        }
        if (*(int *)(iVar13 + 0x7b8) != 0) {
          local_34[*(byte *)(iVar13 + 0x7bc) >> 2 & 3] = '\x01';
        }
        if (local_34[0] == -1) {
          uVar7 = 0;
        }
        else if (local_34[1] == -1) {
          uVar7 = 1;
        }
        else if (local_34[2] == -1) {
          uVar7 = 2;
        }
        else if (local_34[3] == -1) {
          uVar7 = 3;
        }
        else {
          uVar7 = 0xffffffff;
        }
        *(byte *)(iVar13 + 0x7bc) =
             (byte)((uVar7 & 0xff) << 4) & 0x30 | *(byte *)(iVar13 + 0x7bc) & 0xcf;
        uVar10 = FUN_8002e088(dVar14,param_2,param_3,param_4,param_5,param_6,param_7,param_8,puVar9,
                              4,0xff,0xffffffff,*(uint **)(iVar6 + 0x30),in_r8,in_r9,in_r10);
        *(undefined4 *)(iVar13 + 0x7b0) = uVar10;
        dVar14 = (double)FUN_80037e24(iVar6,*(int *)(iVar13 + 0x7b0),
                                      *(byte *)(iVar13 + 0x7bc) >> 4 & 3);
      }
    }
    else if (*(int *)(iVar13 + 0x7b0) != 0) {
      *(float *)(iVar13 + 0x7b4) = *(float *)(iVar13 + 0x7b4) - FLOAT_803dc074;
      dVar14 = (double)*(float *)(iVar13 + 0x7b4);
      if (dVar14 <= (double)FLOAT_803e306c) {
        dVar14 = (double)FUN_80138d68(dVar14,param_2,param_3,param_4,param_5,param_6,param_7,param_8
                                      ,iVar6,iVar13,(int *)(iVar13 + 0x7b0));
      }
    }
    if ((bVar3) && ((*(uint *)(iVar13 + 0x54) & 0x200) == 0)) {
      *(float *)(iVar13 + 0x7ac) = FLOAT_803e3188;
      if ((*(int *)(iVar13 + 0x7a8) == 0) && (uVar7 = FUN_8002e144(), (uVar7 & 0xff) != 0)) {
        uVar7 = FUN_80022264(0,3);
        if (uVar7 == 0) {
          if (bVar4) {
            iVar8 = *(int *)(iVar6 + 0xb8);
            if (((*(byte *)(iVar8 + 0x58) >> 6 & 1) == 0) &&
               (((0x2f < *(short *)(iVar6 + 0xa0) || (*(short *)(iVar6 + 0xa0) < 0x29)) &&
                (bVar11 = FUN_8000b598(iVar6,0x10), !bVar11)))) {
              in_r8 = 0;
              dVar14 = (double)FUN_800394f0(iVar6,iVar8 + 0x3a8,0x359,0x500,0xffffffff,0);
            }
          }
          else if ((((bVar5) &&
                    (iVar8 = *(int *)(iVar6 + 0xb8), (*(byte *)(iVar8 + 0x58) >> 6 & 1) == 0)) &&
                   ((0x2f < *(short *)(iVar6 + 0xa0) || (*(short *)(iVar6 + 0xa0) < 0x29)))) &&
                  (bVar11 = FUN_8000b598(iVar6,0x10), !bVar11)) {
            in_r8 = 0;
            dVar14 = (double)FUN_800394f0(iVar6,iVar8 + 0x3a8,0x358,0x500,0xffffffff,0);
          }
        }
        puVar9 = FUN_8002becc(0x20,0x175);
        local_38[0] = -1;
        local_38[1] = -1;
        local_38[2] = -1;
        if (*(int *)(iVar13 + 0x7a8) != 0) {
          local_38[*(byte *)(iVar13 + 0x7bc) >> 6] = '\x01';
        }
        if (*(int *)(iVar13 + 0x7b0) != 0) {
          local_38[*(byte *)(iVar13 + 0x7bc) >> 4 & 3] = '\x01';
        }
        if (*(int *)(iVar13 + 0x7b8) != 0) {
          local_38[*(byte *)(iVar13 + 0x7bc) >> 2 & 3] = '\x01';
        }
        if (local_38[0] == -1) {
          uVar7 = 0;
        }
        else if (local_38[1] == -1) {
          uVar7 = 1;
        }
        else if (local_38[2] == -1) {
          uVar7 = 2;
        }
        else if (local_38[3] == -1) {
          uVar7 = 3;
        }
        else {
          uVar7 = 0xffffffff;
        }
        *(byte *)(iVar13 + 0x7bc) = (byte)((uVar7 & 0xff) << 6) | *(byte *)(iVar13 + 0x7bc) & 0x3f;
        uVar10 = FUN_8002e088(dVar14,param_2,param_3,param_4,param_5,param_6,param_7,param_8,puVar9,
                              4,0xff,0xffffffff,*(uint **)(iVar6 + 0x30),in_r8,in_r9,in_r10);
        *(undefined4 *)(iVar13 + 0x7a8) = uVar10;
        FUN_80037e24(iVar6,*(int *)(iVar13 + 0x7a8),(ushort)(*(byte *)(iVar13 + 0x7bc) >> 6));
      }
    }
    else if (*(int *)(iVar13 + 0x7a8) != 0) {
      *(float *)(iVar13 + 0x7ac) = *(float *)(iVar13 + 0x7ac) - FLOAT_803dc074;
      if ((double)*(float *)(iVar13 + 0x7ac) <= (double)FLOAT_803e306c) {
        FUN_80138d68((double)*(float *)(iVar13 + 0x7ac),param_2,param_3,param_4,param_5,param_6,
                     param_7,param_8,iVar6,iVar13,(int *)(iVar13 + 0x7a8));
      }
    }
  }
  FUN_80286880();
  return;
}

