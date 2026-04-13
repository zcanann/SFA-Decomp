// Function: FUN_802bf088
// Entry: 802bf088
// Size: 988 bytes

/* WARNING: Removing unreachable block (ram,0x802bf444) */
/* WARNING: Removing unreachable block (ram,0x802bf43c) */
/* WARNING: Removing unreachable block (ram,0x802bf0a0) */
/* WARNING: Removing unreachable block (ram,0x802bf098) */

void FUN_802bf088(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)

{
  float fVar1;
  short *psVar2;
  uint uVar3;
  undefined2 *puVar4;
  int iVar5;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  int iVar6;
  int iVar7;
  int iVar8;
  undefined8 extraout_f1;
  undefined8 uVar9;
  double in_f30;
  double dVar10;
  double in_f31;
  double dVar11;
  double in_ps30_1;
  double in_ps31_1;
  float local_68;
  float local_64;
  float local_60;
  undefined2 local_5c [4];
  float local_54;
  float local_50;
  undefined4 local_4c;
  float local_48;
  longlong local_40;
  float local_18;
  float fStack_14;
  float local_8;
  float fStack_4;
  
  local_8 = (float)in_f31;
  fStack_4 = (float)in_ps31_1;
  local_18 = (float)in_f30;
  fStack_14 = (float)in_ps30_1;
  psVar2 = (short *)FUN_8028683c();
  iVar8 = *(int *)(psVar2 + 0x5c);
  uVar9 = extraout_f1;
  FUN_8002bac4();
  *(undefined *)(*(int *)(psVar2 + 0x2a) + 0x6e) = 0;
  *(undefined *)(*(int *)(psVar2 + 0x2a) + 0x6f) = 0;
  if ((*(int *)(iVar8 + 0xb54) == 0) && (uVar3 = FUN_8002e144(), (uVar3 & 0xff) != 0)) {
    puVar4 = FUN_8002becc(0x18,0x6f5);
    iVar5 = FUN_8002e088(uVar9,param_2,param_3,param_4,param_5,param_6,param_7,param_8,puVar4,4,
                         *(undefined *)(psVar2 + 0x56),0xffffffff,*(uint **)(psVar2 + 0x18),in_r8,
                         in_r9,in_r10);
    FUN_80037e24((int)psVar2,iVar5,2);
    *(int *)(iVar8 + 0xb54) = iVar5;
  }
  *(undefined2 *)(iVar8 + 0x14de) = 5;
  *(byte *)((int)psVar2 + 0xaf) = *(byte *)((int)psVar2 + 0xaf) & 0xf7;
  if (*(char *)(iVar8 + 0x14e6) == '\x02') {
    FUN_8011f6d0(0x13);
    *(byte *)((int)psVar2 + 0xaf) = *(byte *)((int)psVar2 + 0xaf) | 8;
    *(undefined *)(*(int *)(psVar2 + 0x2a) + 0x6a) = 0xf4;
    *(undefined *)(*(int *)(psVar2 + 0x2a) + 0x6b) = 0xf4;
    local_40 = (longlong)(int)FLOAT_803dc074;
    FUN_802bee58(psVar2);
  }
  else {
    *(undefined *)(*(int *)(psVar2 + 0x2a) + 0x6a) = 0;
    *(undefined *)(*(int *)(psVar2 + 0x2a) + 0x6b) = 0;
    fVar1 = FLOAT_803e8f9c;
    *(float *)(iVar8 + 0x294) = FLOAT_803e8f9c;
    *(float *)(iVar8 + 0x284) = fVar1;
    *(float *)(iVar8 + 0x280) = fVar1;
    *(float *)(psVar2 + 0x12) = fVar1;
    *(float *)(psVar2 + 0x14) = fVar1;
    *(float *)(psVar2 + 0x16) = fVar1;
    FUN_802bee58(psVar2);
  }
  FUN_8003b408((int)psVar2,iVar8 + 0x38c);
  FUN_80039030((int)psVar2,(char *)(iVar8 + 0x3bc));
  FUN_80115330();
  if ((*(byte *)((int)psVar2 + 0xaf) & 1) != 0) {
    *(byte *)(iVar8 + 0x14ec) = *(byte *)(iVar8 + 0x14ec) & 0xef | 0x10;
    iVar5 = (**(code **)(*DAT_803dd6e8 + 0x20))(0xc1);
    if (iVar5 == 0) {
      if ((*(char *)(iVar8 + 0x14f4) != -1) &&
         (iVar5 = (**(code **)(*DAT_803dd6e8 + 0x1c))(), iVar5 == 0)) {
        if ((*(byte *)(iVar8 + 0x14ec) >> 3 & 1) == 0) {
          (**(code **)(*DAT_803dd6d4 + 0x48))((int)*(char *)(iVar8 + 0x14f4),psVar2,0xffffffff);
          FUN_80014b68(0,0x100);
        }
        else {
          *(byte *)(iVar8 + 0x14ec) = *(byte *)(iVar8 + 0x14ec) & 0xef | 0x10;
        }
      }
    }
    else {
      (**(code **)(*DAT_803dd6d4 + 0x48))(1,psVar2,0xffffffff);
      FUN_80014b68(0,0x100);
      *(short *)(iVar8 + 0x14e2) = *(short *)(iVar8 + 0x14e2) + 4;
      uVar3 = FUN_80020078(0xc1);
      FUN_800201ac(0xc1,uVar3 - 1);
    }
  }
  *(byte *)(iVar8 + 0x264) = *(byte *)(iVar8 + 0x264) | 0x10;
  dVar10 = (double)*(float *)(psVar2 + 0x14);
  *(float *)(psVar2 + 0x14) = FLOAT_803e8f9c;
  *(uint *)(iVar8 + 0x314) = *(uint *)(iVar8 + 0x314) & 0xfffffff8;
  fVar1 = FLOAT_803e9018;
  if (*(byte *)(iVar8 + 0x13fe) == 8) {
    fVar1 = FLOAT_803e9014;
  }
  FUN_8006ef48((double)*(float *)(iVar8 + 0x280),(double)fVar1,psVar2,*(undefined4 *)(iVar8 + 0x314)
               ,(uint)*(byte *)(iVar8 + 0x13fe),iVar8 + 0xb18,iVar8 + 4);
  *(float *)(psVar2 + 0x14) = (float)dVar10;
  if ((*(ushort *)(iVar8 + 0x1430) & 8) != 0) {
    local_68 = FLOAT_803e8fd4 * *(float *)(psVar2 + 0x12);
    local_64 = FLOAT_803e8f9c;
    local_60 = FLOAT_803e8fd4 * *(float *)(psVar2 + 0x16);
    iVar6 = 0;
    dVar10 = (double)FLOAT_803e8ff4;
    dVar11 = (double)FLOAT_803e8fd0;
    iVar5 = iVar8;
    do {
      local_50 = (float)(dVar10 * (double)*(float *)(psVar2 + 0x12) +
                        (double)*(float *)(iVar5 + 0xb18));
      local_4c = *(undefined4 *)(iVar5 + 0xb1c);
      local_48 = (float)(dVar10 * (double)*(float *)(psVar2 + 0x16) +
                        (double)*(float *)(iVar5 + 0xb20));
      local_54 = (float)dVar11;
      local_5c[0] = 2;
      iVar7 = 2;
      do {
        (**(code **)(*DAT_803dd708 + 8))(psVar2,0x7e6,local_5c,0x200001,0xffffffff,&local_68);
        iVar7 = iVar7 + -1;
      } while (iVar7 != 0);
      iVar5 = iVar5 + 0xc;
      iVar6 = iVar6 + 1;
    } while (iVar6 < 4);
    *(ushort *)(iVar8 + 0x1430) = *(ushort *)(iVar8 + 0x1430) & 0xfff7;
  }
  FUN_80286888();
  return;
}

