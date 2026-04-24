// Function: FUN_8022013c
// Entry: 8022013c
// Size: 1604 bytes

void FUN_8022013c(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)

{
  ushort uVar1;
  short sVar2;
  short sVar3;
  ushort *puVar4;
  uint uVar5;
  byte bVar8;
  undefined2 *puVar6;
  ushort *puVar7;
  undefined4 in_r9;
  undefined4 in_r10;
  int iVar9;
  int iVar10;
  int iVar11;
  int *piVar12;
  double extraout_f1;
  double dVar13;
  double extraout_f1_00;
  double dVar14;
  
  puVar4 = (ushort *)FUN_80286840();
  piVar12 = *(int **)(puVar4 + 0x5c);
  iVar11 = *(int *)(puVar4 + 0x26);
  dVar13 = extraout_f1;
  FUN_8002bac4();
  if (*(int *)(puVar4 + 0x62) == 0) {
    iVar9 = FUN_80036974((int)puVar4,(undefined4 *)0x0,(int *)0x0,(uint *)0x0);
    uVar1 = puVar4[0x23];
    if (uVar1 == 0x70a) {
      if ((iVar9 == 0xf) || (iVar9 == 0xe)) {
        *(byte *)((int)piVar12 + 0x41) = *(byte *)((int)piVar12 + 0x41) & 0xbf;
        FUN_800803f8(piVar12 + 9);
        dVar13 = (double)FUN_80080404((float *)(piVar12 + 9),300);
      }
    }
    else if (((0x709 < (short)uVar1) || (uVar1 != 0x6f9)) && (iVar9 == 0x10)) {
      iVar9 = *(int *)(puVar4 + 0x26);
      FUN_8002b128(puVar4,300);
      dVar13 = (double)FUN_800201ac((int)*(short *)(iVar9 + 0x1e),1);
      *(byte *)((int)piVar12 + 0x41) = *(byte *)((int)piVar12 + 0x41) & 0xef | 0x10;
    }
  }
  else {
    dVar13 = (double)FUN_80035ff8((int)puVar4);
    if ((*(byte *)((int)piVar12 + 0x41) >> 2 & 1) == 0) goto LAB_80220768;
    *(byte *)((int)piVar12 + 0x41) = *(byte *)((int)piVar12 + 0x41) & 0xf7 | 8;
  }
  if (((*(byte *)((int)piVar12 + 0x41) >> 4 & 1) == 0) &&
     ((int)*(short *)(iVar11 + 0x1e) != 0xffffffff)) {
    uVar5 = FUN_80020078((int)*(short *)(iVar11 + 0x1e));
    if (*(byte *)((int)piVar12 + 0x41) >> 7 != uVar5) {
      uVar5 = FUN_80020078((int)*(short *)(iVar11 + 0x1e));
      uVar5 = countLeadingZeros(uVar5);
      uVar5 = uVar5 >> 5 & 1;
      *(byte *)((int)piVar12 + 0x41) = (byte)(uVar5 << 6) | *(byte *)((int)piVar12 + 0x41) & 0xbf;
      if (uVar5 == 0) {
        dVar13 = (double)FUN_800803f8(piVar12 + 9);
      }
      else {
        iVar9 = *(int *)(puVar4 + 0x26);
        iVar10 = *(int *)(puVar4 + 0x5c);
        dVar13 = (double)FUN_800803f8((undefined4 *)(iVar10 + 0x24));
        sVar2 = *(short *)(iVar9 + 0x1a);
        if (sVar2 != 0) {
          sVar3 = *(short *)(iVar9 + 0x20);
          if (sVar3 == 0) {
            dVar13 = (double)FUN_80080404((float *)(iVar10 + 0x24),sVar2 * 0x3c);
          }
          else if (sVar3 < 0) {
            uVar5 = FUN_80022264(1,sVar2 * 0x3c);
            dVar13 = (double)FUN_80080404((float *)(iVar10 + 0x24),(short)uVar5);
          }
          else {
            dVar13 = (double)FUN_80080404((float *)(iVar10 + 0x24),sVar3 * 0x3c);
            if (*(short *)(iVar9 + 0x1a) <= *(short *)(iVar9 + 0x20)) {
              *(byte *)(iVar10 + 0x41) = *(byte *)(iVar10 + 0x41) & 0xbf;
            }
          }
        }
      }
    }
    uVar5 = FUN_80020078((int)*(short *)(iVar11 + 0x1e));
    *(byte *)((int)piVar12 + 0x41) =
         (byte)((uVar5 & 0xff) << 7) | *(byte *)((int)piVar12 + 0x41) & 0x7f;
  }
  if (((*(byte *)((int)piVar12 + 0x41) >> 6 & 1) != 0) &&
     (((puVar4[0x58] & 0x800) != 0 || (*(int *)(puVar4 + 0x62) != 0)))) {
    param_2 = (double)FLOAT_803e7808;
    dVar13 = (double)FUN_80098da4(puVar4,piVar12[0xd] & 0xff,0,0,(undefined4 *)0x0);
  }
  bVar8 = FUN_8002b11c((int)puVar4);
  if (bVar8 == 0) {
    if ((*(byte *)((int)piVar12 + 0x41) >> 4 & 1) != 0) {
      *(byte *)((int)piVar12 + 0x41) = *(byte *)((int)piVar12 + 0x41) & 0xbf | 0x40;
      *(byte *)((int)piVar12 + 0x41) = *(byte *)((int)piVar12 + 0x41) & 0xef;
      dVar13 = (double)FUN_800201ac((int)*(short *)(iVar11 + 0x1e),
                                    (uint)(*(byte *)((int)piVar12 + 0x41) >> 7));
    }
    uVar5 = FUN_800803dc((float *)(piVar12 + 9));
    if ((uVar5 != 0) && ((*(byte *)((int)piVar12 + 0x41) >> 6 & 1) == 0)) {
      param_2 = (double)(float)piVar12[9];
      dVar13 = DOUBLE_803e7838;
      if ((double)(float)((double)CONCAT44(0x43300000,(int)DAT_803dcfb0 ^ 0x80000000) -
                         DOUBLE_803e7838) <= param_2) {
        if (piVar12[0xb] != 0) {
          dVar13 = (double)FUN_8001dc30((double)FLOAT_803e7830,piVar12[0xb],'\0');
          iVar9 = FUN_8001dc28(piVar12[0xb]);
          if (iVar9 == 0) {
            dVar13 = (double)FUN_8001cc00((uint *)(piVar12 + 0xb));
          }
        }
      }
      else if ((piVar12[0xb] == 0) && ((*(byte *)((int)piVar12 + 0x41) & 1) != 0)) {
        iVar9 = FUN_8001cd60(puVar4,0xff,0x80,0,0);
        piVar12[0xb] = iVar9;
        dVar13 = extraout_f1_00;
        if (piVar12[0xb] != 0) {
          FUN_8001dc30((double)FLOAT_803e780c,piVar12[0xb],'\0');
          FUN_8001dc30((double)FLOAT_803e7810,piVar12[0xb],'\x01');
          if (puVar4[0x23] == 0x6f9) {
            FUN_8001d7f4((double)(FLOAT_803dcfb4 * *(float *)(puVar4 + 4)),param_2,param_3,param_4,
                         param_5,param_6,param_7,param_8,piVar12[0xb],0,0,0xb4,0xff,100,in_r9,in_r10
                        );
          }
          else {
            FUN_8001d7f4((double)(FLOAT_803dcfb4 * *(float *)(puVar4 + 4)),param_2,param_3,param_4,
                         param_5,param_6,param_7,param_8,piVar12[0xb],0,0xff,0x80,0,100,in_r9,in_r10
                        );
          }
          param_3 = (double)FLOAT_803e7814;
          FUN_8001de4c((double)FLOAT_803e780c,(double)FLOAT_803e780c,param_3,(int *)piVar12[0xb]);
          dVar14 = (double)(FLOAT_803e7818 * *(float *)(puVar4 + 4));
          dVar13 = (double)FLOAT_803e781c;
          if ((dVar13 <= dVar14) && (dVar13 = dVar14, (double)FLOAT_803e7820 < dVar14)) {
            dVar13 = (double)FLOAT_803e7820;
          }
          dVar14 = (double)(float)((double)FLOAT_803e7824 + dVar14);
          param_2 = (double)FLOAT_803e7828;
          if ((param_2 <= dVar14) && (param_2 = dVar14, (double)FLOAT_803e782c < dVar14)) {
            param_2 = (double)FLOAT_803e782c;
          }
          dVar13 = (double)FUN_8001dcfc(dVar13,param_2,piVar12[0xb]);
        }
      }
    }
    iVar9 = FUN_80080434((float *)(piVar12 + 9));
    if (iVar9 != 0) {
      if (*(short *)(iVar11 + 0x1a) != 0) {
        dVar13 = (double)FUN_80080404((float *)(piVar12 + 9),*(short *)(iVar11 + 0x1a) * 0x3c);
      }
      uVar5 = countLeadingZeros(*(byte *)((int)piVar12 + 0x41) >> 6 & 1);
      *(byte *)((int)piVar12 + 0x41) =
           (byte)((uVar5 >> 5 & 0xff) << 6) & 0x40 | *(byte *)((int)piVar12 + 0x41) & 0xbf;
    }
  }
  else {
    *(byte *)((int)piVar12 + 0x41) = *(byte *)((int)piVar12 + 0x41) & 0xbf;
    *(byte *)((int)piVar12 + 0x41) = *(byte *)((int)piVar12 + 0x41) & 0xef | 0x10;
  }
  if (((*(byte *)((int)piVar12 + 0x41) >> 6 & 1) != 0) &&
     (iVar11 = FUN_80080434((float *)(piVar12 + 10)), iVar11 != 0)) {
    iVar9 = *(int *)(puVar4 + 0x26);
    iVar11 = *(int *)(puVar4 + 0x5c);
    puVar6 = FUN_8002becc(0x24,0x1b5);
    *(undefined *)(puVar6 + 2) = 2;
    *(undefined *)((int)puVar6 + 0x19) = *(undefined *)(iVar11 + 0x40);
    puVar6[0xd] = *(undefined2 *)(iVar9 + 0x1c);
    *(undefined4 *)(puVar6 + 4) = *(undefined4 *)(puVar4 + 6);
    *(undefined4 *)(puVar6 + 6) = *(undefined4 *)(puVar4 + 8);
    *(undefined4 *)(puVar6 + 8) = *(undefined4 *)(puVar4 + 10);
    if (puVar6 == (undefined2 *)0x0) {
      puVar7 = (ushort *)0x0;
    }
    else {
      puVar7 = (ushort *)
               FUN_8021ff1c(dVar13,param_2,param_3,param_4,param_5,param_6,param_7,param_8,piVar12,
                            (int)puVar4,(uint)puVar6);
    }
    if (puVar7 != (ushort *)0x0) {
      *(undefined4 *)(puVar7 + 6) = *(undefined4 *)(puVar4 + 6);
      *(undefined4 *)(puVar7 + 8) = *(undefined4 *)(puVar4 + 8);
      *(undefined4 *)(puVar7 + 10) = *(undefined4 *)(puVar4 + 10);
      *puVar7 = *puVar4;
      puVar7[1] = puVar4[1];
      *(float *)(puVar7 + 0x14) = FLOAT_803dcfac;
    }
    FUN_800803f8(piVar12 + 10);
    FUN_80080404((float *)(piVar12 + 10),(short)DAT_803dcfb8);
  }
  if ((*(byte *)((int)piVar12 + 0x41) >> 6 & 1) != 0) {
    if ((*(byte *)((int)piVar12 + 0x41) >> 5 & 1) == 0) {
      FUN_8000b4f0((uint)puVar4,0x32c,3);
    }
    FUN_8000d904((uint)puVar4,0x32d,2);
  }
  *(byte *)((int)piVar12 + 0x41) =
       (byte)((*(byte *)((int)piVar12 + 0x41) >> 6 & 1) << 5) |
       *(byte *)((int)piVar12 + 0x41) & 0xdf;
  if (piVar12[0xb] != 0) {
    FUN_8001d774(piVar12[0xb]);
  }
LAB_80220768:
  FUN_8028688c();
  return;
}

