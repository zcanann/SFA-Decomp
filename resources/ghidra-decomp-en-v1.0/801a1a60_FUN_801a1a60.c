// Function: FUN_801a1a60
// Entry: 801a1a60
// Size: 744 bytes

void FUN_801a1a60(int param_1)

{
  float fVar1;
  float fVar2;
  float fVar3;
  int iVar4;
  int iVar5;
  double dVar6;
  undefined4 local_80;
  undefined4 local_7c;
  undefined4 local_78;
  float local_74;
  float local_70;
  float local_6c;
  undefined auStack104 [28];
  undefined4 local_4c;
  undefined4 local_48;
  undefined4 local_44;
  char local_17;
  
  iVar5 = *(int *)(param_1 + 0xb8);
  iVar4 = FUN_800379dc(*(undefined4 *)(iVar5 + 0x10));
  if ((iVar4 == 0) && (*(int *)(iVar5 + 0x10) != 0)) {
    FUN_80037cb0(param_1);
    *(undefined4 *)(iVar5 + 0x10) = 0;
  }
  if (((*(char *)(iVar5 + 0x17) == '\0') && (iVar4 = FUN_80080150(iVar5 + 0x18), iVar4 == 0)) &&
     (iVar4 = FUN_80080150(iVar5 + 0x1c), iVar4 == 0)) {
    if (*(int *)(iVar5 + 0xc) != 0) {
      FUN_80062e84(param_1,*(int *)(iVar5 + 0xc),1);
      *(undefined4 *)(iVar5 + 0xc) = 0;
    }
    if (*(char *)(iVar5 + 0x4a) < '\0') {
      fVar1 = *(float *)(param_1 + 0x10);
      fVar2 = *(float *)(param_1 + 0x84);
      fVar3 = FLOAT_803e4324 * FLOAT_803db418;
      local_74 = (*(float *)(param_1 + 0xc) - *(float *)(param_1 + 0x80)) * fVar3;
      local_6c = (*(float *)(param_1 + 0x14) - *(float *)(param_1 + 0x88)) * fVar3;
      *(float *)(iVar5 + 0x20) = local_74 + *(float *)(iVar5 + 0x20);
      *(float *)(iVar5 + 0x24) = (fVar1 - fVar2) * fVar3 + *(float *)(iVar5 + 0x24);
      *(float *)(iVar5 + 0x28) = local_6c + *(float *)(iVar5 + 0x28);
      fVar2 = FLOAT_803e4328;
      fVar1 = FLOAT_803e42c0;
      local_70 = FLOAT_803e42c0;
      *(float *)(iVar5 + 0x20) = FLOAT_803e4328 * *(float *)(iVar5 + 0x20);
      *(float *)(iVar5 + 0x24) = fVar2 * *(float *)(iVar5 + 0x24);
      *(float *)(iVar5 + 0x28) = fVar2 * *(float *)(iVar5 + 0x28);
      *(float *)(iVar5 + 0x24) = fVar1;
      *(byte *)(iVar5 + 0x49) = *(byte *)(iVar5 + 0x49) | 1;
    }
    if ((*(char *)(iVar5 + 0x15) == '\0') &&
       (iVar4 = FUN_800640cc((double)FLOAT_803e432c,param_1 + 0x80,param_1 + 0xc,1,auStack104,
                             param_1,8,0xffffffff,0xff,0), iVar4 != 0)) {
      if (local_17 == '\x14') {
        *(undefined *)(iVar5 + 0x16) = 4;
      }
      if ((*(char *)(iVar5 + 0x4a) < '\0') && (local_17 == '\x03')) {
        FUN_801a0e04(param_1,0);
        FUN_80036fa4(param_1,0x16);
      }
      else {
        local_80 = local_4c;
        local_7c = local_48;
        local_78 = local_44;
        FUN_8002273c(&local_80,param_1 + 0x24,param_1 + 0x24);
        FUN_8002273c(&local_80,iVar5 + 0x20,iVar5 + 0x20);
        fVar1 = FLOAT_803e4330;
        *(float *)(param_1 + 0x24) = FLOAT_803e4330 * *(float *)(param_1 + 0x24);
        *(float *)(param_1 + 0x28) = fVar1 * *(float *)(param_1 + 0x28);
        *(float *)(param_1 + 0x2c) = fVar1 * *(float *)(param_1 + 0x2c);
        *(float *)(iVar5 + 0x20) = fVar1 * *(float *)(iVar5 + 0x20);
        *(float *)(iVar5 + 0x24) = fVar1 * *(float *)(iVar5 + 0x24);
        *(float *)(iVar5 + 0x28) = fVar1 * *(float *)(iVar5 + 0x28);
        if (FLOAT_803e4334 < *(float *)(iVar5 + 0x54)) {
          dVar6 = (double)FUN_802477f0(iVar5 + 0x20);
          if ((double)FLOAT_803dbe84 < dVar6) {
            FUN_8000bb18(param_1,0x446);
          }
          *(float *)(iVar5 + 0x54) = FLOAT_803e42c0;
        }
      }
    }
    *(undefined4 *)(param_1 + 0x80) = *(undefined4 *)(param_1 + 0xc);
    *(undefined4 *)(param_1 + 0x84) = *(undefined4 *)(param_1 + 0x10);
    *(undefined4 *)(param_1 + 0x88) = *(undefined4 *)(param_1 + 0x14);
  }
  return;
}

