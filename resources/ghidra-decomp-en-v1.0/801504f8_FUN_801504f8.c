// Function: FUN_801504f8
// Entry: 801504f8
// Size: 1048 bytes

void FUN_801504f8(undefined4 param_1,undefined4 param_2,int param_3,int param_4,int param_5,
                 int param_6)

{
  float fVar1;
  int iVar2;
  int iVar3;
  undefined uVar4;
  int iVar5;
  uint uVar6;
  undefined *puVar7;
  undefined *puVar8;
  undefined *puVar9;
  undefined8 uVar10;
  
  uVar10 = FUN_802860cc();
  fVar1 = FLOAT_803e2740;
  iVar3 = (int)((ulonglong)uVar10 >> 0x20);
  iVar5 = (int)uVar10;
  uVar6 = (uint)*(byte *)(iVar5 + 0x33b);
  puVar9 = (&PTR_DAT_8031f17c)[uVar6 * 10];
  puVar8 = (&PTR_DAT_8031f190)[uVar6 * 10];
  puVar7 = (&PTR_DAT_8031f188)[uVar6 * 10];
  uVar4 = 0;
  if (uVar6 == 5) {
    *(uint *)(iVar5 + 0x2e8) = *(uint *)(iVar5 + 0x2e8) | 0x10;
    uVar4 = 0;
  }
  else {
    if (param_4 == 0xe) {
      param_6 = param_6 * 10;
    }
    if (*(ushort *)(iVar3 + 0xa0) == (ushort)(byte)puVar9[0x128]) {
      uVar4 = 0;
    }
    else if (param_4 == 0x10) {
      *(uint *)(iVar5 + 0x2e8) = *(uint *)(iVar5 + 0x2e8) | 0x28;
      uVar4 = 0;
    }
    else if (((*(uint *)(iVar5 + 0x2dc) & 0x40) == 0) &&
            (((&PTR_DAT_8031f18c)[uVar6 * 10][param_5] == '\0' ||
             ((1 < param_4 - 0xeU && (param_4 != 0x13)))))) {
      if (param_4 == 0x11) {
        uVar6 = 0x18;
      }
      else {
        uVar6 = *(byte *)(iVar5 + 0x2f1) & 0x1f;
        if (0x18 < uVar6) {
          uVar6 = 0;
        }
      }
      *(float *)(iVar5 + 0x324) = FLOAT_803e2740;
      if ((*(byte *)(iVar5 + 0x2f1) & 0x18) == 0) {
        *(float *)(iVar5 + 0x334) = fVar1;
      }
      else if ((*(byte *)(iVar5 + 0x2f1) & 1) == 0) {
        *(float *)(iVar5 + 0x334) = FLOAT_803e276c;
      }
      else {
        *(float *)(iVar5 + 0x334) = FLOAT_803e2768;
      }
      if ((*(float *)(iVar5 + 0x328) == FLOAT_803e2740) || (*(ushort *)(iVar5 + 0x338) == 0)) {
        iVar2 = uVar6 * 0xc;
        FUN_8014d08c((double)*(float *)(puVar9 + iVar2),iVar3,iVar5,puVar9[iVar2 + 8],0,
                     *(uint *)(puVar9 + iVar2 + 4) & 0xff);
        FUN_80030304((double)*(float *)(&DAT_8031dd30 + (uint)(byte)puVar9[iVar2 + 8] * 4),iVar3);
        *(ushort *)(iVar5 + 0x338) = (ushort)(byte)puVar9[iVar2 + 9];
        *(float *)(iVar5 + 0x328) =
             (float)((double)CONCAT44(0x43300000,(uint)*(ushort *)(iVar5 + 0x2ec)) - DOUBLE_803e2770
                    );
      }
      else {
        iVar2 = (uint)(byte)puVar7[(uint)*(ushort *)(iVar5 + 0x338) * 0x10 + 0xb] * 0x10;
        FUN_8014d08c((double)*(float *)(puVar7 + iVar2),iVar3,iVar5,puVar7[iVar2 + 8],0,
                     *(uint *)(puVar7 + iVar2 + 4) & 0xff);
        FUN_80030304((double)*(float *)(&DAT_8031dd30 +
                                       (uint)(byte)puVar7[(uint)(byte)puVar7[(uint)*(ushort *)
                                                                                    (iVar5 + 0x338)
                                                                             * 0x10 + 0xb] * 0x10 +
                                                          8] * 4),iVar3);
      }
      *(uint *)(iVar5 + 0x2e8) = *(uint *)(iVar5 + 0x2e8) | 8;
      if (*(short *)(param_3 + 0x44) == 0x1c) {
        uVar4 = 0;
      }
      else if ((*(int *)(param_3 + 0xc4) == 0) ||
              (*(short *)(*(int *)(param_3 + 0xc4) + 0x44) != 0x1c)) {
        if ((*(byte *)(iVar5 + 0x2f1) & 0x10) == 0) {
          *(undefined *)(iVar5 + 0x2f5) = 0;
        }
        else {
          param_6 = 0x14;
        }
        if ((int)(uint)*(ushort *)(iVar5 + 0x2b0) < param_6) {
          *(undefined2 *)(iVar5 + 0x2b0) = 0;
        }
        else {
          *(ushort *)(iVar5 + 0x2b0) = *(ushort *)(iVar5 + 0x2b0) - (short)param_6;
        }
        if (*(short *)(iVar5 + 0x2b0) == 0) {
          FUN_8000bb18(iVar3,0x13);
        }
        else {
          FUN_8000bb18(iVar3,0x14);
        }
        if ((((param_4 != 0x1a) && (param_4 != 0x1f)) && (*(short *)(param_3 + 0x46) != 0x6d)) &&
           (*(short *)(param_3 + 0x46) != 0x754)) {
          FUN_8000bb18(iVar3,0x22);
        }
      }
      else {
        uVar4 = 0;
      }
    }
    else if (param_4 != 0x11) {
      if (((param_4 != 0x1a) && (*(short *)(param_3 + 0x46) != 0x6d)) &&
         (*(short *)(param_3 + 0x46) != 0x754)) {
        FUN_8000bb18(iVar3,0x255);
        FUN_8000bb18(iVar3,0x16);
      }
      *(uint *)(iVar5 + 0x2e8) = *(uint *)(iVar5 + 0x2e8) | 0x10;
      iVar2 = (uint)*(byte *)(iVar5 + 0x33c) * 0xc;
      FUN_8014d08c((double)*(float *)(puVar8 + iVar2),iVar3,iVar5,puVar8[iVar2 + 8],0,
                   *(uint *)(puVar8 + iVar2 + 4) & 0xff);
      FUN_80030304((double)*(float *)(&DAT_8031dd30 +
                                     (uint)(byte)puVar8[(uint)*(byte *)(iVar5 + 0x33c) * 0xc + 8] *
                                     4),iVar3);
      if (puVar8[(uint)*(byte *)(iVar5 + 0x33c) * 0xc + 10] != '\0') {
        *(undefined *)(iVar5 + 0x33a) = puVar8[(uint)*(byte *)(iVar5 + 0x33c) * 0xc + 10];
      }
      uVar4 = puVar8[(uint)*(byte *)(iVar5 + 0x33c) * 0xc + 9];
      *(undefined4 *)(iVar5 + 0x32c) = *(undefined4 *)(iVar5 + 0x330);
      fVar1 = FLOAT_803e2740;
      *(float *)(iVar5 + 0x324) = FLOAT_803e2740;
      *(float *)(iVar5 + 0x334) = fVar1;
    }
  }
  FUN_80286118(uVar4);
  return;
}

