// Function: FUN_8020be04
// Entry: 8020be04
// Size: 672 bytes

void FUN_8020be04(int param_1)

{
  short sVar1;
  int iVar2;
  undefined4 uVar3;
  int iVar4;
  uint *puVar5;
  double dVar6;
  double local_20;
  
  puVar5 = *(uint **)(param_1 + 0xb8);
  iVar4 = *(int *)(param_1 + 0x4c);
  iVar2 = FUN_80080150(puVar5 + 3);
  if (iVar2 == 0) {
    FUN_8000da58(param_1,0x479);
    if ((char)*(byte *)((int)puVar5 + 0x79) < '\0') {
      *(byte *)((int)puVar5 + 0x79) = *(byte *)((int)puVar5 + 0x79) & 0x7f;
    }
    sVar1 = *(short *)(param_1 + 0x46);
    if (sVar1 == 0x727) {
      FUN_8002b9ec();
      iVar2 = FUN_802972a8();
      if (iVar2 == 0) {
        FUN_80035df4(param_1,0xe,1,0);
      }
      else {
        FUN_80035dac(param_1);
        FUN_80035f20(param_1);
      }
    }
    else if ((sVar1 < 0x727) && (sVar1 == 0x709)) {
      iVar2 = FUN_8002b9ec();
      dVar6 = (double)FUN_80021704(iVar2 + 0x18,param_1 + 0x18);
      local_20 = (double)CONCAT44(0x43300000,(int)*(short *)(iVar4 + 0x1c) << 1 ^ 0x80000000);
      if (dVar6 < (double)(float)(local_20 - DOUBLE_803e65a0)) {
        uVar3 = FUN_8002b9ec();
        FUN_80036450(uVar3,param_1,5,1,0);
      }
    }
    if (*puVar5 == 0) {
      iVar2 = *(int *)(param_1 + 0x4c);
      FUN_80035f20(param_1);
      *puVar5 = (uint)*(byte *)(iVar2 + 0x19);
      FUN_80035974(param_1,(int)(short)puVar5[0x1d]);
    }
    if ((*(short *)(param_1 + 0x46) == 0x709) && ((float)puVar5[0x1a] < FLOAT_803e658c)) {
      local_20 = (double)CONCAT44(0x43300000,(uint)DAT_803db410);
      puVar5[0x1a] = (uint)(FLOAT_803e65ac * (float)(local_20 - DOUBLE_803e65b8) +
                           (float)puVar5[0x1a]);
      *(float *)(param_1 + 8) =
           ((float)puVar5[0x1a] *
           *(float *)(*(int *)(param_1 + 0x50) + 4) *
           (float)((double)CONCAT44(0x43300000,(int)*(short *)(iVar4 + 0x1c) ^ 0x80000000) -
                  DOUBLE_803e65a0)) / FLOAT_803e65b0;
    }
  }
  else {
    if ((float)puVar5[3] <
        (float)((double)CONCAT44(0x43300000,(int)*(short *)(iVar4 + 0x1c) ^ 0x80000000) -
               DOUBLE_803e65a0)) {
      FUN_80035f20(param_1);
      FUN_80035974(param_1,(int)((FLOAT_803e65a8 +
                                 (float)((double)CONCAT44(0x43300000,
                                                          (int)*(short *)(iVar4 + 0x1c) ^ 0x80000000
                                                         ) - DOUBLE_803e65a0)) - (float)puVar5[3]));
    }
    iVar2 = FUN_800801a8(puVar5 + 3);
    if (iVar2 != 0) {
      *(ushort *)(param_1 + 6) = *(ushort *)(param_1 + 6) & 0xbfff;
      *(byte *)((int)puVar5 + 0x79) = *(byte *)((int)puVar5 + 0x79) & 0x7f | 0x80;
      if (*(int *)(iVar4 + 0x14) == -1) {
        FUN_8002cbc4(param_1);
      }
    }
  }
  return;
}

