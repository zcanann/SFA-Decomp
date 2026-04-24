// Function: FUN_800254e4
// Entry: 800254e4
// Size: 944 bytes

void FUN_800254e4(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,int param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)

{
  char cVar1;
  short sVar2;
  short *psVar3;
  int iVar4;
  char *pcVar5;
  int iVar6;
  uint uVar7;
  uint uVar8;
  int iVar9;
  int iVar10;
  undefined4 uVar11;
  int iVar12;
  int iVar13;
  uint uVar14;
  uint uVar15;
  int iVar16;
  undefined8 extraout_f1;
  undefined8 uVar17;
  char *local_38;
  uint local_34;
  uint uStack_30;
  char *local_2c;
  int local_28 [10];
  
  uVar17 = FUN_8028683c();
  psVar3 = DAT_803dd7e0;
  iVar6 = (int)((ulonglong)uVar17 >> 0x20);
  uVar8 = (uint)uVar17;
  uVar14 = 0;
  uVar7 = uVar8 << 1;
  uVar11 = 0x10;
  uVar17 = FUN_800490c4(extraout_f1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0x2d,
                        DAT_803dd7e0,uVar7,0x10,param_13,param_14,param_15,param_16);
  sVar2 = *psVar3;
  if (*(ushort *)(iVar6 + 0xec) != 0) {
    uVar15 = (uint)*(ushort *)(iVar6 + 0xec) * 2 + 8;
    if (0x800 < uVar15) {
      uVar17 = FUN_80137c30(uVar17,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                            s_Warning__Model_animation_buffer_o_802cb784,uVar15,uVar7,uVar11,
                            param_13,param_14,param_15,param_16);
    }
    uVar17 = FUN_800490c4(uVar17,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0x31,
                          DAT_803dd7e0,(uVar8 & 0xfffffffc) << 2,0x20,param_13,param_14,param_15,
                          param_16);
    uVar8 = uVar8 & 3;
    *(undefined4 *)(iVar6 + 0x80) = *(undefined4 *)(DAT_803dd7e0 + uVar8 * 2);
    iVar9 = *(int *)(DAT_803dd7e0 + uVar8 * 2);
    iVar4 = *(int *)(DAT_803dd7e0 + uVar8 * 2 + 2);
    if ((*(ushort *)(iVar6 + 2) & 0x40) == 0) {
      uVar17 = FUN_800490c4(uVar17,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0x2e,
                            DAT_803dd7e4,(int)sVar2,uVar15,param_13,param_14,param_15,param_16);
      *(int *)(iVar6 + 0x6c) = DAT_803dd7e4;
    }
    else {
      *(int *)(iVar6 + 0x6c) = param_11;
      for (uVar14 = uVar15; (uVar14 & 7) != 0; uVar14 = uVar14 + 1) {
      }
      param_11 = param_11 + uVar14;
      uVar17 = FUN_800490c4(uVar17,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0x2e,
                            *(undefined4 *)(iVar6 + 0x6c),(int)sVar2,uVar14,param_13,param_14,
                            param_15,param_16);
    }
    iVar10 = 0;
    *(undefined2 *)(iVar6 + 0x70) = 0;
    iVar16 = 1;
    for (iVar13 = 0; iVar13 < (int)(uint)*(ushort *)(iVar6 + 0xec); iVar13 = iVar13 + 1) {
      iVar12 = iVar16;
      if (*(short *)(*(int *)(iVar6 + 0x6c) + iVar10) == -1) {
        iVar12 = iVar16 + 1;
        *(short *)(iVar6 + iVar16 * 2 + 0x70) = (short)iVar13 + 1;
      }
      iVar10 = iVar10 + 2;
      iVar16 = iVar12;
    }
    if ((*(ushort *)(iVar6 + 2) & 0x40) == 0) {
      *(undefined4 *)(iVar6 + 0x6c) = 0;
      *(int *)(iVar6 + 100) = param_11;
      iVar16 = (uint)*(ushort *)(iVar6 + 0xec) * 4;
      iVar10 = param_11 + iVar16;
      for (uVar14 = uVar14 + iVar16; (uVar14 & 7) != 0; uVar14 = uVar14 + 1) {
        iVar10 = iVar10 + 1;
      }
      *(int *)(iVar6 + 0x68) = iVar10;
      uVar17 = FUN_800490c4(uVar17,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0x32,
                            *(undefined4 *)(iVar6 + 0x68),*(uint *)(iVar6 + 0x80),iVar4 - iVar9,
                            iVar13,param_14,param_15,param_16);
      iVar4 = 0;
      iVar16 = 0;
      iVar9 = 0;
      do {
        sVar2 = *(short *)(DAT_803dd7e4 + iVar16);
        iVar10 = (int)sVar2;
        if (iVar10 == -1) {
          *(undefined4 *)(*(int *)(iVar6 + 100) + iVar9) = 0;
        }
        else {
          uVar7 = FUN_800431a4();
          if ((((uVar7 & 0x100000) == 0) || (*(short *)(iVar6 + 4) == 1)) ||
             (*(short *)(iVar6 + 4) == 3)) {
            iVar13 = FUN_80013c30(DAT_803dd7d0,iVar10,(uint)&local_38);
            if (iVar13 == 0) {
              uVar7 = *(uint *)(DAT_803dd7cc + iVar10 * 4);
              uVar17 = FUN_80046644(uVar17,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                                    0x30,0,uVar7,0,&local_34,iVar10,1,param_16);
              local_38 = (char *)FUN_80023d8c(local_34,10);
              FUN_80046644(uVar17,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0x30,
                           local_38,uVar7,local_34,&uStack_30,iVar10,0,param_16);
              *local_38 = '\x01';
              uVar17 = FUN_80013d08(DAT_803dd7d0,sVar2,(uint)&local_38);
              pcVar5 = local_38;
            }
            else {
              *local_38 = *local_38 + '\x01';
              pcVar5 = local_38;
            }
          }
          else {
            pcVar5 = (char *)0x0;
          }
          *(char **)(*(int *)(iVar6 + 100) + iVar9) = pcVar5;
          if (*(int *)(*(int *)(iVar6 + 100) + iVar9) == 0) {
            iVar9 = 0;
            for (iVar16 = 0; iVar16 < iVar4; iVar16 = iVar16 + 1) {
              local_2c = *(char **)(*(int *)(iVar6 + 100) + iVar9);
              if ((local_2c != (char *)0x0) &&
                 (cVar1 = *local_2c, *local_2c = cVar1 + -1, (char)(cVar1 + -1) < '\x01')) {
                FUN_80013b9c(DAT_803dd7d0,(int)&local_2c,local_28);
                FUN_80013c98(DAT_803dd7d0,local_28[0]);
                FUN_800238c4((uint)local_2c);
              }
              iVar9 = iVar9 + 4;
            }
            *(undefined4 *)(iVar6 + 100) = 0;
            break;
          }
        }
        iVar16 = iVar16 + 2;
        iVar9 = iVar9 + 4;
        iVar4 = iVar4 + 1;
      } while (iVar4 < (int)(uint)*(ushort *)(iVar6 + 0xec));
    }
    else {
      *(undefined4 *)(iVar6 + 100) = 0;
    }
  }
  FUN_80286888();
  return;
}

