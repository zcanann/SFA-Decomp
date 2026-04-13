// Function: FUN_801af104
// Entry: 801af104
// Size: 708 bytes

void FUN_801af104(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)

{
  uint uVar1;
  short *psVar2;
  undefined uVar4;
  undefined2 *puVar3;
  int iVar5;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  int *piVar6;
  int iVar7;
  undefined8 extraout_f1;
  undefined8 uVar8;
  int local_28;
  int local_24 [9];
  
  psVar2 = (short *)FUN_8028683c();
  iVar7 = *(int *)(psVar2 + 0x26);
  piVar6 = *(int **)(psVar2 + 0x5c);
  if ((*piVar6 == 0) || (piVar6[1] == 0)) {
    iVar7 = FUN_8002e1f4(local_24,&local_28);
    for (local_24[0] = 0; local_24[0] < local_28; local_24[0] = local_24[0] + 1) {
      iVar5 = *(int *)(iVar7 + local_24[0] * 4);
      if (*(short *)(iVar5 + 0x46) == 0x164) {
        *piVar6 = iVar5;
      }
      if (*(short *)(iVar5 + 0x46) == 0x168) {
        piVar6[1] = iVar5;
      }
    }
  }
  else {
    uVar4 = (**(code **)(**(int **)(piVar6[1] + 0x68) + 0x24))();
    *(undefined *)(piVar6 + 2) = uVar4;
    if (*(char *)(piVar6 + 2) == '\0') {
      uVar1 = (uint)*(byte *)(psVar2 + 0x1b) + (uint)DAT_803dc070 * -8;
      if ((int)uVar1 < 0) {
        uVar1 = 0;
      }
    }
    else {
      uVar1 = (uint)*(byte *)(psVar2 + 0x1b) + (uint)DAT_803dc070 * 8;
      if (0xff < uVar1) {
        uVar1 = 0xff;
      }
    }
    *(char *)(psVar2 + 0x1b) = (char)uVar1;
    if ((*(int *)(psVar2 + 0x7a) == 0) &&
       (uVar8 = extraout_f1, uVar1 = FUN_8002e144(), (uVar1 & 0xff) != 0)) {
      iVar5 = 0;
      do {
        puVar3 = FUN_8002becc(0x24,0x301);
        *(undefined4 *)(puVar3 + 4) = *(undefined4 *)(psVar2 + 6);
        *(undefined4 *)(puVar3 + 6) = *(undefined4 *)(psVar2 + 8);
        *(undefined4 *)(puVar3 + 8) = *(undefined4 *)(psVar2 + 10);
        uVar1 = FUN_80022264(0,0xffff);
        *(char *)(puVar3 + 0xc) = (char)uVar1;
        uVar1 = FUN_80022264(200,400);
        puVar3[0xd] = (short)uVar1;
        uVar1 = FUN_80022264(0,1);
        if (uVar1 == 0) {
          puVar3[0xd] = -puVar3[0xd];
        }
        uVar1 = FUN_80022264(200,400);
        puVar3[0xe] = (short)uVar1;
        uVar1 = FUN_80022264(0,1);
        if (uVar1 == 0) {
          puVar3[0xe] = -puVar3[0xe];
        }
        *(undefined *)(puVar3 + 2) = *(undefined *)(iVar7 + 4);
        *(undefined *)(puVar3 + 3) = *(undefined *)(iVar7 + 6);
        *(undefined *)((int)puVar3 + 5) = 1;
        *(undefined *)((int)puVar3 + 7) = 0xff;
        uVar8 = FUN_8002e088(uVar8,param_2,param_3,param_4,param_5,param_6,param_7,param_8,puVar3,5,
                             *(undefined *)(psVar2 + 0x56),0xffffffff,*(uint **)(psVar2 + 0x18),
                             in_r8,in_r9,in_r10);
        iVar5 = iVar5 + 1;
      } while (iVar5 < 10);
      psVar2[0x7a] = 0;
      psVar2[0x7b] = 1;
    }
    iVar7 = *piVar6;
    FUN_8002ba34((double)(*(float *)(iVar7 + 0xc) - *(float *)(psVar2 + 6)),
                 (double)((FLOAT_803e545c + *(float *)(iVar7 + 0x10)) - *(float *)(psVar2 + 8)),
                 (double)(*(float *)(iVar7 + 0x14) - *(float *)(psVar2 + 10)),(int)psVar2);
    *psVar2 = *psVar2 + (ushort)DAT_803dc070 * 0x100;
    psVar2[1] = psVar2[1] + (ushort)DAT_803dc070 * 0x20;
    psVar2[2] = psVar2[2] + (ushort)DAT_803dc070 * 0x40;
    psVar2[0x18] = 0;
    psVar2[0x19] = 0;
  }
  FUN_80286888();
  return;
}

