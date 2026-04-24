// Function: FUN_80220908
// Entry: 80220908
// Size: 848 bytes

void FUN_80220908(void)

{
  short sVar1;
  short sVar2;
  undefined2 *puVar3;
  uint uVar4;
  int iVar5;
  int iVar6;
  int iVar7;
  undefined4 *puVar8;
  undefined8 uVar9;
  
  uVar9 = FUN_80286840();
  puVar3 = (undefined2 *)((ulonglong)uVar9 >> 0x20);
  iVar5 = (int)uVar9;
  puVar8 = *(undefined4 **)(puVar3 + 0x5c);
  if ((int)*(short *)(iVar5 + 0x1c) != 0) {
    *(float *)(puVar3 + 4) =
         FLOAT_803e7840 *
         (float)((double)CONCAT44(0x43300000,(int)*(short *)(iVar5 + 0x1c) ^ 0x80000000) -
                DOUBLE_803e7838) * *(float *)(*(int *)(puVar3 + 0x28) + 4);
  }
  if ((int)*(short *)(iVar5 + 0x1e) == 0xffffffff) {
    *(byte *)((int)puVar8 + 0x41) = *(byte *)((int)puVar8 + 0x41) & 0xbf | 0x40;
  }
  else {
    uVar4 = FUN_80020078((int)*(short *)(iVar5 + 0x1e));
    *(byte *)((int)puVar8 + 0x41) =
         (byte)((uVar4 & 0xff) << 6) & 0x40 | *(byte *)((int)puVar8 + 0x41) & 0xbf;
  }
  *(code **)(puVar3 + 0x5e) = FUN_80220788;
  iVar6 = *(int *)(puVar3 + 0x26);
  iVar7 = *(int *)(puVar3 + 0x5c);
  FUN_800803f8((undefined4 *)(iVar7 + 0x24));
  sVar1 = *(short *)(iVar6 + 0x1a);
  if (sVar1 != 0) {
    sVar2 = *(short *)(iVar6 + 0x20);
    if (sVar2 == 0) {
      FUN_80080404((float *)(iVar7 + 0x24),sVar1 * 0x3c);
    }
    else if (sVar2 < 0) {
      uVar4 = FUN_80022264(1,sVar1 * 0x3c);
      FUN_80080404((float *)(iVar7 + 0x24),(short)uVar4);
    }
    else {
      FUN_80080404((float *)(iVar7 + 0x24),sVar2 * 0x3c);
      if (*(short *)(iVar6 + 0x1a) <= *(short *)(iVar6 + 0x20)) {
        *(byte *)(iVar7 + 0x41) = *(byte *)(iVar7 + 0x41) & 0xbf;
      }
    }
  }
  *(undefined2 *)(puVar8 + 0xf) = 0;
  *(undefined2 *)((int)puVar8 + 0x3e) = 0;
  sVar1 = puVar3[0x23];
  if (sVar1 != 0x70a) {
    if (sVar1 < 0x70a) {
      if (sVar1 == 0x6f9) {
        puVar8[0xd] = 10;
        *(undefined *)(puVar8 + 0x10) = 1;
        puVar8[0xe] = FLOAT_803dcfa8;
        goto LAB_80220b28;
      }
    }
    else {
      if (sVar1 == 0x731) {
        puVar8[0xd] = 0xd;
        *(undefined *)(puVar8 + 0x10) = 2;
        puVar8[0xe] = FLOAT_803e780c;
        goto LAB_80220b28;
      }
      if (sVar1 < 0x731) {
        if (0x72f < sVar1) {
          puVar8[0xd] = 0xc;
          *(undefined *)(puVar8 + 0x10) = 2;
          puVar8[0xe] = FLOAT_803e780c;
          goto LAB_80220b28;
        }
      }
      else if (sVar1 < 0x733) {
        puVar8[0xd] = 0xe;
        *(undefined *)(puVar8 + 0x10) = 2;
        puVar8[0xe] = FLOAT_803e780c;
        goto LAB_80220b28;
      }
    }
  }
  puVar8[0xd] = 9;
  *(undefined *)(puVar8 + 0x10) = 0;
  puVar8[0xe] = -FLOAT_803dcfa8;
  *(undefined2 *)(puVar8 + 0xf) = 0x32c;
  *(undefined2 *)((int)puVar8 + 0x3e) = 0x32e;
LAB_80220b28:
  *puVar8 = 0;
  puVar8[1] = 0;
  puVar8[2] = 0;
  puVar8[3] = 0;
  puVar8[4] = 0;
  puVar8[5] = 0;
  puVar8[6] = 0;
  puVar8[7] = 0;
  *(undefined *)(puVar8 + 8) = 0;
  puVar3[2] = 0;
  *puVar3 = (short)((int)*(char *)(iVar5 + 0x18) << 8);
  puVar3[1] = (ushort)*(byte *)(iVar5 + 0x19) << 8;
  FUN_80036018((int)puVar3);
  *(byte *)((int)puVar8 + 0x41) = *(byte *)((int)puVar8 + 0x41) & 0xef;
  puVar8[0xc] = 0;
  uVar4 = FUN_80020078((int)*(short *)(iVar5 + 0x1e));
  uVar4 = countLeadingZeros(uVar4);
  *(byte *)((int)puVar8 + 0x41) =
       (byte)((uVar4 >> 5 & 0xff) << 7) | *(byte *)((int)puVar8 + 0x41) & 0x7f;
  *(byte *)((int)puVar8 + 0x41) =
       ((*(byte *)(iVar5 + 0x22) & 1) == 0) << 1 | *(byte *)((int)puVar8 + 0x41) & 0xfd;
  *(byte *)((int)puVar8 + 0x41) =
       (*(byte *)(iVar5 + 0x22) & 2) == 0 | *(byte *)((int)puVar8 + 0x41) & 0xfe;
  FUN_800803f8(puVar8 + 10);
  FUN_80080404((float *)(puVar8 + 10),0x14);
  FUN_800372f8((int)puVar3,0x4a);
  *(byte *)((int)puVar8 + 0x41) = *(byte *)((int)puVar8 + 0x41) & 0xfb;
  puVar8[0xb] = 0;
  FUN_8028688c();
  return;
}

