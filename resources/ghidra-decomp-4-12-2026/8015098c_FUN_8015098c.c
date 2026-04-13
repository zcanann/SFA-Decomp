// Function: FUN_8015098c
// Entry: 8015098c
// Size: 1048 bytes

void FUN_8015098c(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,int param_11,int param_12,int param_13,
                 int param_14,undefined4 param_15,undefined4 param_16)

{
  float fVar1;
  uint uVar2;
  int iVar3;
  uint uVar4;
  int iVar5;
  undefined *puVar6;
  int iVar7;
  undefined *puVar8;
  undefined *puVar9;
  undefined8 uVar10;
  
  uVar10 = FUN_80286830();
  fVar1 = FLOAT_803e33d8;
  uVar2 = (uint)((ulonglong)uVar10 >> 0x20);
  iVar3 = (int)uVar10;
  uVar4 = (uint)*(byte *)(iVar3 + 0x33b);
  puVar9 = (&PTR_DAT_8031fdcc)[uVar4 * 10];
  puVar8 = (&PTR_DAT_8031fde0)[uVar4 * 10];
  puVar6 = (&PTR_DAT_8031fdd8)[uVar4 * 10];
  if (uVar4 == 5) {
    *(uint *)(iVar3 + 0x2e8) = *(uint *)(iVar3 + 0x2e8) | 0x10;
  }
  else {
    iVar5 = param_14;
    if (param_12 == 0xe) {
      iVar5 = param_14 * 10;
    }
    if (*(ushort *)(uVar2 + 0xa0) != (ushort)(byte)puVar9[0x128]) {
      if (param_12 == 0x10) {
        *(uint *)(iVar3 + 0x2e8) = *(uint *)(iVar3 + 0x2e8) | 0x28;
      }
      else if (((*(uint *)(iVar3 + 0x2dc) & 0x40) == 0) &&
              (((&PTR_DAT_8031fddc)[uVar4 * 10][param_13] == '\0' ||
               ((1 < param_12 - 0xeU && (param_12 != 0x13)))))) {
        if (param_12 == 0x11) {
          uVar4 = 0x18;
        }
        else {
          uVar4 = *(byte *)(iVar3 + 0x2f1) & 0x1f;
          if (0x18 < uVar4) {
            uVar4 = 0;
          }
        }
        *(float *)(iVar3 + 0x324) = FLOAT_803e33d8;
        if ((*(byte *)(iVar3 + 0x2f1) & 0x18) == 0) {
          *(float *)(iVar3 + 0x334) = fVar1;
        }
        else if ((*(byte *)(iVar3 + 0x2f1) & 1) == 0) {
          *(float *)(iVar3 + 0x334) = FLOAT_803e3404;
        }
        else {
          *(float *)(iVar3 + 0x334) = FLOAT_803e3400;
        }
        if ((*(float *)(iVar3 + 0x328) == FLOAT_803e33d8) || (*(ushort *)(iVar3 + 0x338) == 0)) {
          iVar7 = uVar4 * 0xc;
          FUN_8014d504((double)*(float *)(puVar9 + iVar7),param_2,param_3,param_4,param_5,param_6,
                       param_7,param_8,uVar2,iVar3,(uint)(byte)puVar9[iVar7 + 8],0,
                       *(uint *)(puVar9 + iVar7 + 4) & 0xff,param_14,param_15,param_16);
          FUN_800303fc((double)*(float *)(&DAT_8031e980 + (uint)(byte)puVar9[iVar7 + 8] * 4),uVar2);
          *(ushort *)(iVar3 + 0x338) = (ushort)(byte)puVar9[iVar7 + 9];
          *(float *)(iVar3 + 0x328) =
               (float)((double)CONCAT44(0x43300000,(uint)*(ushort *)(iVar3 + 0x2ec)) -
                      DOUBLE_803e3408);
        }
        else {
          iVar7 = (uint)(byte)puVar6[(uint)*(ushort *)(iVar3 + 0x338) * 0x10 + 0xb] * 0x10;
          FUN_8014d504((double)*(float *)(puVar6 + iVar7),param_2,param_3,param_4,param_5,param_6,
                       param_7,param_8,uVar2,iVar3,(uint)(byte)puVar6[iVar7 + 8],0,
                       *(uint *)(puVar6 + iVar7 + 4) & 0xff,param_14,param_15,param_16);
          FUN_800303fc((double)*(float *)(&DAT_8031e980 +
                                         (uint)(byte)puVar6[(uint)(byte)puVar6[(uint)*(ushort *)
                                                                                      (iVar3 + 0x338
                                                                                      ) * 0x10 + 0xb
                                                                              ] * 0x10 + 8] * 4),
                       uVar2);
        }
        *(uint *)(iVar3 + 0x2e8) = *(uint *)(iVar3 + 0x2e8) | 8;
        if ((*(short *)(param_11 + 0x44) != 0x1c) &&
           ((*(int *)(param_11 + 0xc4) == 0 ||
            (*(short *)(*(int *)(param_11 + 0xc4) + 0x44) != 0x1c)))) {
          if ((*(byte *)(iVar3 + 0x2f1) & 0x10) == 0) {
            *(undefined *)(iVar3 + 0x2f5) = 0;
          }
          else {
            iVar5 = 0x14;
          }
          if ((int)(uint)*(ushort *)(iVar3 + 0x2b0) < iVar5) {
            *(undefined2 *)(iVar3 + 0x2b0) = 0;
          }
          else {
            *(ushort *)(iVar3 + 0x2b0) = *(ushort *)(iVar3 + 0x2b0) - (short)iVar5;
          }
          if (*(short *)(iVar3 + 0x2b0) == 0) {
            FUN_8000bb38(uVar2,0x13);
          }
          else {
            FUN_8000bb38(uVar2,0x14);
          }
          if ((((param_12 != 0x1a) && (param_12 != 0x1f)) && (*(short *)(param_11 + 0x46) != 0x6d))
             && (*(short *)(param_11 + 0x46) != 0x754)) {
            FUN_8000bb38(uVar2,0x22);
          }
        }
      }
      else if (param_12 != 0x11) {
        if (((param_12 != 0x1a) && (*(short *)(param_11 + 0x46) != 0x6d)) &&
           (*(short *)(param_11 + 0x46) != 0x754)) {
          FUN_8000bb38(uVar2,0x255);
          FUN_8000bb38(uVar2,0x16);
        }
        *(uint *)(iVar3 + 0x2e8) = *(uint *)(iVar3 + 0x2e8) | 0x10;
        iVar5 = (uint)*(byte *)(iVar3 + 0x33c) * 0xc;
        FUN_8014d504((double)*(float *)(puVar8 + iVar5),param_2,param_3,param_4,param_5,param_6,
                     param_7,param_8,uVar2,iVar3,(uint)(byte)puVar8[iVar5 + 8],0,
                     *(uint *)(puVar8 + iVar5 + 4) & 0xff,param_14,param_15,param_16);
        FUN_800303fc((double)*(float *)(&DAT_8031e980 +
                                       (uint)(byte)puVar8[(uint)*(byte *)(iVar3 + 0x33c) * 0xc + 8]
                                       * 4),uVar2);
        if (puVar8[(uint)*(byte *)(iVar3 + 0x33c) * 0xc + 10] != '\0') {
          *(undefined *)(iVar3 + 0x33a) = puVar8[(uint)*(byte *)(iVar3 + 0x33c) * 0xc + 10];
        }
        *(undefined4 *)(iVar3 + 0x32c) = *(undefined4 *)(iVar3 + 0x330);
        fVar1 = FLOAT_803e33d8;
        *(float *)(iVar3 + 0x324) = FLOAT_803e33d8;
        *(float *)(iVar3 + 0x334) = fVar1;
      }
    }
  }
  FUN_8028687c();
  return;
}

