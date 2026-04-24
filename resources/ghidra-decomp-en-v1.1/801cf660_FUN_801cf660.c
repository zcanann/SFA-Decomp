// Function: FUN_801cf660
// Entry: 801cf660
// Size: 1120 bytes

void FUN_801cf660(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 short *param_9)

{
  char cVar1;
  undefined4 uVar2;
  undefined uVar3;
  uint uVar4;
  float *in_r7;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  int iVar5;
  int iVar6;
  undefined *puVar7;
  double dVar8;
  
  puVar7 = &DAT_80327400;
  iVar6 = *(int *)(param_9 + 0x5c);
  iVar5 = *(int *)(param_9 + 0x26);
  if ((*(byte *)(iVar6 + 0x43c) & 0x20) != 0) {
    param_1 = (**(code **)(*DAT_803dd728 + 0x20))(param_9,iVar6 + 0x16c);
    *(byte *)(iVar6 + 0x43c) = *(byte *)(iVar6 + 0x43c) & 0xdf;
  }
  uVar2 = FUN_8002bac4();
  *(undefined4 *)(iVar6 + 0x28) = uVar2;
  if (*(int *)(iVar6 + 0x28) == 0) {
    return;
  }
  if (((&DAT_803274f4)[*(byte *)(iVar6 + 0x408)] & 0x20) == 0) {
    param_9[0x58] = param_9[0x58] & 0xfbff;
    *(uint *)(*(int *)(param_9 + 0x32) + 0x30) = *(uint *)(*(int *)(param_9 + 0x32) + 0x30) | 4;
  }
  else {
    param_9[0x58] = param_9[0x58] | 0x400;
    *(uint *)(*(int *)(param_9 + 0x32) + 0x30) =
         *(uint *)(*(int *)(param_9 + 0x32) + 0x30) & 0xfffffffb;
  }
  if (((&DAT_803274f4)[*(byte *)(iVar6 + 0x408)] & 8) == 0) {
    if (((&DAT_803274f4)[*(byte *)(iVar6 + 0x408)] & 2) != 0) {
      puVar7 = &DAT_80327414;
    }
    in_r7 = (float *)(iVar6 + 0x50);
    uVar3 = FUN_8003549c(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,
                         puVar7,1,(uint)*(byte *)(iVar6 + 0x3d4),in_r7,in_r8,in_r9,in_r10);
    *(undefined *)(iVar6 + 0x3d4) = uVar3;
    if (*(char *)(iVar6 + 0x3d4) != '\0') {
      FUN_8003a260((int)param_9,iVar6 + 0x40c);
      FUN_8003b408((int)param_9,iVar6 + 0x40c);
      return;
    }
  }
  dVar8 = FUN_80021794((float *)(param_9 + 0xc),(float *)(*(int *)(iVar6 + 0x28) + 0x18));
  *(float *)(iVar6 + 0x18) = (float)dVar8;
  cVar1 = *(char *)(iVar5 + 0x1d);
  if (cVar1 == '\x02') {
    FUN_801cf2e0((int)param_9,iVar6);
    goto LAB_801cf840;
  }
  if (cVar1 < '\x02') {
    if (cVar1 == '\0') {
      FUN_801cf3c0((uint)param_9,iVar6);
      goto LAB_801cf840;
    }
    if (cVar1 < '\0') goto LAB_801cf840;
  }
  else {
    if (cVar1 == '\x04') {
      FUN_801ce870(dVar8,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,iVar6,iVar5
                  );
      goto LAB_801cf840;
    }
    if ('\x03' < cVar1) goto LAB_801cf840;
  }
  FUN_801cefc8(param_9,iVar6,iVar5);
LAB_801cf840:
  if (((&DAT_803274f4)[*(byte *)(iVar6 + 0x408)] & 1) == 0) {
    *(byte *)((int)param_9 + 0xaf) = *(byte *)((int)param_9 + 0xaf) & 0xef;
    if ((((&DAT_803274f4)[*(byte *)(iVar6 + 0x408)] & 0x10) == 0) ||
       (iVar5 = FUN_8012f000(), iVar5 == -1)) {
      in_r7 = (float *)0x0;
      in_r8 = 2;
      FUN_8002b7b0((int)param_9,0,0,0,'\0','\x02');
    }
    else {
      in_r7 = (float *)0x0;
      in_r8 = 4;
      FUN_8002b7b0((int)param_9,0,0,0,'\0','\x04');
    }
  }
  else {
    *(byte *)((int)param_9 + 0xaf) = *(byte *)((int)param_9 + 0xaf) | 0x10;
  }
  uVar4 = (uint)*(byte *)(iVar6 + 0x408);
  iVar5 = (int)*(short *)(&DAT_80327468 + uVar4 * 2);
  if (param_9[0x50] != iVar5) {
    if ((double)*(float *)(&DAT_80327498 + uVar4 * 4) <= (double)FLOAT_803e5ea4) {
      FUN_8003042c((double)FLOAT_803e5ea8,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                   param_9,iVar5,0,uVar4,in_r7,in_r8,in_r9,in_r10);
    }
    else {
      FUN_8003042c((double)FLOAT_803e5ea4,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                   param_9,iVar5,0,uVar4,in_r7,in_r8,in_r9,in_r10);
    }
    *(undefined4 *)(iVar6 + 0x4c) =
         *(undefined4 *)(&DAT_80327498 + (uint)*(byte *)(iVar6 + 0x408) * 4);
  }
  iVar5 = FUN_8002fb40((double)*(float *)(iVar6 + 0x4c),(double)FLOAT_803dc074);
  if (iVar5 == 0) {
    *(byte *)(iVar6 + 0x43c) = *(byte *)(iVar6 + 0x43c) & 0xfd;
  }
  else {
    *(byte *)(iVar6 + 0x43c) = *(byte *)(iVar6 + 0x43c) | 2;
  }
  FUN_8006f0b4((double)FLOAT_803e5ea8,(double)FLOAT_803e5ea8,param_9,iVar6 + 0x440,8,iVar6 + 0x45c,
               iVar6 + 0x16c);
  FUN_801ce548(param_9,iVar6,(byte)(&DAT_803274f4)[*(byte *)(iVar6 + 0x408)] & 4);
  *(byte *)(iVar6 + 0x43c) = *(byte *)(iVar6 + 0x43c) & 0xfb;
  if (((*(byte *)(iVar6 + 0x43c) & 0x10) == 0) && (iVar5 = FUN_8003811c((int)param_9), iVar5 != 0))
  {
    uVar4 = FUN_80022264(1,(uint)**(byte **)(iVar6 + 0x48));
    *(byte *)(iVar6 + 0x43c) = *(byte *)(iVar6 + 0x43c) | 4;
    (**(code **)(*DAT_803dd6d4 + 0x48))
              (*(undefined *)(*(int *)(iVar6 + 0x48) + uVar4),param_9,0xffffffff);
  }
  if ((*(byte *)(iVar6 + 0x43c) & 1) != 0) {
    (**(code **)(*DAT_803dd728 + 0x10))((double)FLOAT_803dc074,param_9,iVar6 + 0x16c);
    (**(code **)(*DAT_803dd728 + 0x14))(param_9,iVar6 + 0x16c);
    (**(code **)(*DAT_803dd728 + 0x18))((double)FLOAT_803dc074,param_9,iVar6 + 0x16c);
  }
  return;
}

