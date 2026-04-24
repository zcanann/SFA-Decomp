// Function: FUN_80143b5c
// Entry: 80143b5c
// Size: 816 bytes

undefined4
FUN_80143b5c(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,int param_9,int *param_10)

{
  float fVar1;
  int iVar2;
  bool bVar5;
  uint uVar3;
  undefined2 *puVar4;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  double dVar6;
  char local_28 [28];
  
  iVar2 = FUN_80144994(param_9,param_10);
  if (iVar2 == 0) {
    iVar2 = FUN_8012f000();
    if (iVar2 == 0xc1) {
      *(undefined *)((int)param_10 + 10) = 0;
    }
    else {
      param_10[0x1ce] = (int)((float)param_10[0x1ce] - FLOAT_803dc074);
      dVar6 = (double)(float)param_10[0x1ce];
      if (dVar6 < (double)FLOAT_803e306c) {
        iVar2 = *(int *)(param_9 + 0xb8);
        if (((*(byte *)(iVar2 + 0x58) >> 6 & 1) == 0) &&
           (((0x2f < *(short *)(param_9 + 0xa0) || (*(short *)(param_9 + 0xa0) < 0x29)) &&
            (bVar5 = FUN_8000b598(param_9,0x10), !bVar5)))) {
          in_r8 = 0;
          dVar6 = (double)FUN_800394f0(param_9,iVar2 + 0x3a8,0x29a,0x100,0xffffffff,0);
        }
        param_10[0x1ce] = (int)FLOAT_803e30d0;
      }
      if ((param_10[0x1ee] == 0) && (uVar3 = FUN_8002e144(), (uVar3 & 0xff) != 0)) {
        puVar4 = FUN_8002becc(0x20,0x17b);
        local_28[0] = -1;
        local_28[1] = -1;
        local_28[2] = -1;
        if (param_10[0x1ea] != 0) {
          local_28[*(byte *)(param_10 + 0x1ef) >> 6] = '\x01';
        }
        if (param_10[0x1ec] != 0) {
          local_28[*(byte *)(param_10 + 0x1ef) >> 4 & 3] = '\x01';
        }
        if (param_10[0x1ee] != 0) {
          local_28[*(byte *)(param_10 + 0x1ef) >> 2 & 3] = '\x01';
        }
        if (local_28[0] == -1) {
          uVar3 = 0;
        }
        else if (local_28[1] == -1) {
          uVar3 = 1;
        }
        else if (local_28[2] == -1) {
          uVar3 = 2;
        }
        else if (local_28[3] == -1) {
          uVar3 = 3;
        }
        else {
          uVar3 = 0xffffffff;
        }
        *(byte *)(param_10 + 0x1ef) =
             (byte)((uVar3 & 0xff) << 2) & 0xc | *(byte *)(param_10 + 0x1ef) & 0xf3;
        iVar2 = FUN_8002e088(dVar6,param_2,param_3,param_4,param_5,param_6,param_7,param_8,puVar4,4,
                             0xff,0xffffffff,*(uint **)(param_9 + 0x30),in_r8,in_r9,in_r10);
        param_10[0x1ee] = iVar2;
        FUN_80037e24(param_9,param_10[0x1ee],*(byte *)(param_10 + 0x1ef) >> 2 & 3);
        fVar1 = FLOAT_803e306c;
        param_10[0x1f0] = (int)FLOAT_803e306c;
        param_10[0x1f1] = (int)fVar1;
        param_10[0x1f2] = (int)fVar1;
      }
      iVar2 = (**(code **)(*DAT_803dd6d8 + 0x24))(0);
      if (((iVar2 != 0) && ((float)param_10[0x1c7] <= FLOAT_803e306c)) &&
         (uVar3 = FUN_80020078(0xdd), uVar3 != 0)) {
        FUN_8013a778((double)FLOAT_803e30d4,param_9,0x29,0);
        iVar2 = *(int *)(param_9 + 0xb8);
        if (((*(byte *)(iVar2 + 0x58) >> 6 & 1) == 0) &&
           (((0x2f < *(short *)(param_9 + 0xa0) || (*(short *)(param_9 + 0xa0) < 0x29)) &&
            (bVar5 = FUN_8000b598(param_9,0x10), !bVar5)))) {
          FUN_800394f0(param_9,iVar2 + 0x3a8,0x354,0x1000,0xffffffff,0);
        }
        param_10[0x15] = param_10[0x15] | 0x10;
        *(undefined *)((int)param_10 + 10) = 4;
        uVar3 = FUN_80022264(0x78,0xf0);
        param_10[0x1cf] =
             (int)(float)((double)CONCAT44(0x43300000,uVar3 ^ 0x80000000) - DOUBLE_803e30f0);
      }
    }
  }
  else {
    *(undefined *)((int)param_10 + 10) = 0;
  }
  return 1;
}

