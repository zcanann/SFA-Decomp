// Function: FUN_801c1f5c
// Entry: 801c1f5c
// Size: 792 bytes

/* WARNING: Removing unreachable block (ram,0x801c2254) */

void FUN_801c1f5c(undefined4 param_1,undefined4 param_2,undefined4 param_3)

{
  byte bVar1;
  int iVar2;
  char cVar3;
  short sVar4;
  int iVar5;
  int iVar6;
  int *piVar7;
  undefined4 uVar8;
  undefined8 in_f31;
  double dVar9;
  undefined8 uVar10;
  undefined4 local_98;
  byte local_94;
  byte local_93;
  undefined local_92 [2];
  undefined auStack144 [136];
  undefined auStack8 [8];
  
  uVar8 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  uVar10 = FUN_802860d4();
  iVar5 = (int)((ulonglong)uVar10 >> 0x20);
  local_98 = (undefined4)uVar10;
  piVar7 = *(int **)(iVar5 + 0xb8);
  iVar6 = *(int *)(iVar5 + 0x4c);
  if ((*(short *)(iVar6 + 0x1c) == 0) || (iVar2 = FUN_8001ffb4(), iVar2 == 0)) {
    if (*(char *)(iVar5 + 0x36) == '\0') {
      FUN_8000bb18(iVar5,0x475);
    }
    if (*(byte *)(iVar5 + 0x36) < 0x46) {
      *(byte *)(iVar5 + 0x36) = *(byte *)(iVar5 + 0x36) + DAT_803db410;
    }
    else {
      *(undefined *)(iVar5 + 0x36) = 0x46;
    }
  }
  else {
    bVar1 = *(byte *)(iVar5 + 0x36);
    if (bVar1 == 0x46) {
      FUN_8000bb18(iVar5,0x476);
    }
    iVar2 = (uint)bVar1 - (uint)DAT_803db410;
    if (iVar2 < 1) {
      *(undefined *)(iVar5 + 0x36) = 0;
      goto LAB_801c2254;
    }
    *(char *)(iVar5 + 0x36) = (char)iVar2;
  }
  if ((((*(byte *)(iVar6 + 0x18) & 1) != 0) && (*piVar7 != 0)) && (piVar7[0xb] != 0)) {
    dVar9 = (double)*(float *)(iVar5 + 8);
    *(float *)(iVar5 + 8) = FLOAT_803e4df8;
    FUN_8000e820((double)FLOAT_803e4e18,(double)FLOAT_803e4dfc,0,param_3,iVar5,0);
    *(float *)(iVar5 + 8) = (float)dVar9;
    FUN_800799c0();
    FUN_800795e8();
    FUN_80079804();
    if (*(char *)(iVar6 + 0x1b) == '\x01') {
      local_94 = 0xff;
      local_93 = 0xff;
      local_92[0] = 0xff;
    }
    else {
      *(undefined *)(iVar5 + 0x36) = 0xff;
      FUN_800898c8(0,local_92,&local_93,&local_94);
      local_93 = (byte)((uint)local_93 * 200 >> 8);
      local_94 = (byte)((uint)local_94 * 0xaa >> 8);
    }
    if (*(byte *)(iVar5 + 0x36) < 0x47) {
      FUN_80078b4c();
      iVar2 = (int)((uint)*(byte *)(iVar5 + 0x36) * 2) >> 1;
    }
    else {
      FUN_80078740();
      iVar2 = 0xff;
    }
    FUN_8004c2e4(*(undefined4 *)(&DAT_803dbf48 + (uint)*(byte *)(iVar6 + 0x1b) * 4),0);
    FUN_8005d118(&local_98,local_92[0],local_93,local_94,iVar2);
    iVar2 = *(int *)piVar7[0xb];
    for (sVar4 = 0; (int)sVar4 < (int)(*(byte *)(piVar7[0xb] + 8) - 1); sVar4 = sVar4 + 1) {
      FUN_801c0bf8(&DAT_80325e00,(int)*(short *)(piVar7 + 6),iVar2,iVar2 + 0x34,auStack144);
      FUN_8005cf8c(auStack144,&DAT_802c2358,6);
      iVar2 = iVar2 + 0x34;
    }
    if (*(char *)(iVar6 + 0x1b) == '\x01') {
      FUN_8000da58(iVar5,0x480);
      FUN_80078b4c();
      cVar3 = FUN_800221a0(0,*(undefined *)(iVar5 + 0x36));
      FUN_8005d118(&local_98,local_92[0],local_93,local_94,*(char *)(iVar5 + 0x36) + cVar3);
      iVar5 = *(int *)piVar7[0xb];
      for (sVar4 = 0; (int)sVar4 < (int)(*(byte *)(piVar7[0xb] + 8) - 1); sVar4 = sVar4 + 1) {
        FUN_801c0bf8(&DAT_80325e60,(int)*(short *)(piVar7 + 6),iVar5,iVar5 + 0x34,auStack144);
        FUN_8005cf8c(auStack144,&DAT_802c2358,6);
        iVar5 = iVar5 + 0x34;
      }
    }
  }
LAB_801c2254:
  __psq_l0(auStack8,uVar8);
  __psq_l1(auStack8,uVar8);
  FUN_80286120();
  return;
}

