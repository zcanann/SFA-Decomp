// Function: FUN_801cf0ac
// Entry: 801cf0ac
// Size: 1092 bytes

void FUN_801cf0ac(int param_1)

{
  char cVar1;
  undefined4 uVar2;
  undefined uVar3;
  int iVar4;
  int iVar5;
  undefined *puVar6;
  double dVar7;
  
  puVar6 = &DAT_803267c0;
  iVar5 = *(int *)(param_1 + 0xb8);
  iVar4 = *(int *)(param_1 + 0x4c);
  if ((*(byte *)(iVar5 + 0x43c) & 0x20) != 0) {
    *(byte *)(iVar5 + 0x43c) = *(byte *)(iVar5 + 0x43c) & 0xdf;
  }
  uVar2 = FUN_8002b9ec();
  *(undefined4 *)(iVar5 + 0x28) = uVar2;
  if (*(int *)(iVar5 + 0x28) == 0) {
    return;
  }
  if (((&DAT_803268b4)[*(byte *)(iVar5 + 0x408)] & 0x20) == 0) {
    *(ushort *)(param_1 + 0xb0) = *(ushort *)(param_1 + 0xb0) & 0xfbff;
    *(uint *)(*(int *)(param_1 + 100) + 0x30) = *(uint *)(*(int *)(param_1 + 100) + 0x30) | 4;
  }
  else {
    *(ushort *)(param_1 + 0xb0) = *(ushort *)(param_1 + 0xb0) | 0x400;
    *(uint *)(*(int *)(param_1 + 100) + 0x30) =
         *(uint *)(*(int *)(param_1 + 100) + 0x30) & 0xfffffffb;
  }
  if (((&DAT_803268b4)[*(byte *)(iVar5 + 0x408)] & 8) == 0) {
    if (((&DAT_803268b4)[*(byte *)(iVar5 + 0x408)] & 2) != 0) {
      puVar6 = &DAT_803267d4;
    }
    uVar3 = FUN_800353a4(param_1,puVar6,1,*(undefined *)(iVar5 + 0x3d4),iVar5 + 0x50);
    *(undefined *)(iVar5 + 0x3d4) = uVar3;
    if (*(char *)(iVar5 + 0x3d4) != '\0') {
      FUN_8003a168(param_1,iVar5 + 0x40c);
      FUN_8003b310(param_1,iVar5 + 0x40c);
      return;
    }
  }
  dVar7 = (double)FUN_800216d0(param_1 + 0x18,*(int *)(iVar5 + 0x28) + 0x18);
  *(float *)(iVar5 + 0x18) = (float)dVar7;
  cVar1 = *(char *)(iVar4 + 0x1d);
  if (cVar1 == '\x02') {
    FUN_801ced2c(param_1,iVar5,iVar4);
    goto LAB_801cf270;
  }
  if (cVar1 < '\x02') {
    if (cVar1 == '\0') {
      FUN_801cee0c(param_1,iVar5,iVar4);
      goto LAB_801cf270;
    }
    if (cVar1 < '\0') goto LAB_801cf270;
  }
  else {
    if (cVar1 == '\x04') {
      FUN_801ce2bc(param_1,iVar5,iVar4);
      goto LAB_801cf270;
    }
    if ('\x03' < cVar1) goto LAB_801cf270;
  }
  FUN_801cea14(param_1,iVar5,iVar4);
LAB_801cf270:
  if (((&DAT_803268b4)[*(byte *)(iVar5 + 0x408)] & 1) == 0) {
    *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) & 0xef;
    if ((((&DAT_803268b4)[*(byte *)(iVar5 + 0x408)] & 0x10) == 0) ||
       (iVar4 = FUN_8012ebc8(), iVar4 == -1)) {
      FUN_8002b6d8(param_1,0,0,0,0,2);
    }
    else {
      FUN_8002b6d8(param_1,0,0,0,0,4);
    }
  }
  else {
    *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 0x10;
  }
  iVar4 = (int)*(short *)(&DAT_80326828 + (uint)*(byte *)(iVar5 + 0x408) * 2);
  if (*(short *)(param_1 + 0xa0) != iVar4) {
    if (*(float *)(&DAT_80326858 + (uint)*(byte *)(iVar5 + 0x408) * 4) <= FLOAT_803e520c) {
      FUN_80030334((double)FLOAT_803e5210,param_1,iVar4,0);
    }
    else {
      FUN_80030334(param_1,iVar4,0);
    }
    *(undefined4 *)(iVar5 + 0x4c) =
         *(undefined4 *)(&DAT_80326858 + (uint)*(byte *)(iVar5 + 0x408) * 4);
  }
  iVar4 = FUN_8002fa48((double)*(float *)(iVar5 + 0x4c),(double)FLOAT_803db414,param_1,iVar5 + 0x440
                      );
  if (iVar4 == 0) {
    *(byte *)(iVar5 + 0x43c) = *(byte *)(iVar5 + 0x43c) & 0xfd;
  }
  else {
    *(byte *)(iVar5 + 0x43c) = *(byte *)(iVar5 + 0x43c) | 2;
  }
  FUN_8006ef38((double)FLOAT_803e5210,(double)FLOAT_803e5210,param_1,iVar5 + 0x440,8,iVar5 + 0x45c,
               iVar5 + 0x16c);
  FUN_801cdf94(param_1,iVar5,(&DAT_803268b4)[*(byte *)(iVar5 + 0x408)] & 4);
  *(byte *)(iVar5 + 0x43c) = *(byte *)(iVar5 + 0x43c) & 0xfb;
  if (((*(byte *)(iVar5 + 0x43c) & 0x10) == 0) && (iVar4 = FUN_80038024(param_1), iVar4 != 0)) {
    iVar4 = FUN_800221a0(1,**(undefined **)(iVar5 + 0x48));
    *(byte *)(iVar5 + 0x43c) = *(byte *)(iVar5 + 0x43c) | 4;
    (**(code **)(*DAT_803dca54 + 0x48))
              (*(undefined *)(*(int *)(iVar5 + 0x48) + iVar4),param_1,0xffffffff);
  }
  if ((*(byte *)(iVar5 + 0x43c) & 1) != 0) {
    (**(code **)(*DAT_803dcaa8 + 0x10))((double)FLOAT_803db414,param_1,iVar5 + 0x16c);
    (**(code **)(*DAT_803dcaa8 + 0x14))(param_1,iVar5 + 0x16c);
    (**(code **)(*DAT_803dcaa8 + 0x18))((double)FLOAT_803db414,param_1,iVar5 + 0x16c);
  }
  return;
}

