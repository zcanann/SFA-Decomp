// Function: FUN_80095f3c
// Entry: 80095f3c
// Size: 860 bytes

/* WARNING: Removing unreachable block (ram,0x80096278) */
/* WARNING: Removing unreachable block (ram,0x80095f4c) */

void FUN_80095f3c(void)

{
  undefined4 uVar1;
  int iVar2;
  undefined4 *puVar3;
  float *pfVar4;
  int iVar5;
  int iVar6;
  int iVar7;
  double in_f31;
  double dVar8;
  double in_ps31_1;
  undefined8 uVar9;
  ushort local_48 [4];
  undefined4 local_40;
  undefined4 local_3c;
  undefined4 local_38;
  undefined4 local_34;
  float local_8;
  float fStack_4;
  
  local_8 = (float)in_f31;
  fStack_4 = (float)in_ps31_1;
  uVar9 = FUN_80286838();
  uVar1 = (undefined4)((ulonglong)uVar9 >> 0x20);
  if ((((DAT_803ddebc != 0) || (DAT_803ddeac != 0)) || (DAT_803ddeb4 != 0)) || (DAT_803ddea4 != 0))
  {
    FUN_80259288(0);
    if (DAT_803ddebc != 0) {
      FUN_8007cc70();
    }
    iVar2 = 0;
    iVar5 = 0;
    iVar6 = 0;
    iVar7 = 0;
    do {
      puVar3 = (undefined4 *)(DAT_803ddeb8 + iVar5);
      if (*(short *)((int)puVar3 + 0x16) != 0) {
        FUN_8005d294(uVar1,0xff,0xff,0xff,(char)*(short *)((int)puVar3 + 0x16));
        local_3c = *puVar3;
        local_38 = puVar3[1];
        local_34 = puVar3[2];
        local_40 = puVar3[4];
        local_48[0] = *(ushort *)(puVar3 + 5);
        local_48[2] = 0;
        local_48[1] = 0;
        FUN_8000e840((double)FLOAT_803dff6c,uVar1,(int)uVar9,local_48,(float *)0x0);
        FUN_8007d7ec();
        FUN_8005d108(DAT_803ddecc + iVar7,DAT_803ddec8 + iVar6,2);
      }
      iVar5 = iVar5 + 0x1c;
      iVar6 = iVar6 + 0x20;
      iVar7 = iVar7 + 0x40;
      iVar2 = iVar2 + 1;
    } while (iVar2 < 0x1e);
    iVar2 = 0;
    if (DAT_803ddeb4 != 0) {
      FUN_8007bf08(DAT_803dde98,DAT_803dde94);
      FUN_802585d8(9,DAT_803dde80,0xc);
      FUN_802585d8(0xd,DAT_803dde7c,8);
      FUN_80257b5c();
      FUN_802570dc(0,1);
      FUN_802570dc(1,1);
      FUN_802570dc(9,3);
      FUN_802570dc(0xb,3);
      FUN_802570dc(0xd,3);
    }
    iVar5 = 0;
    dVar8 = (double)FLOAT_803dff6c;
    do {
      if ((double)*(float *)(DAT_803ddeb0 + iVar5 + 0x10) < dVar8) {
        FUN_800953f0();
      }
      iVar5 = iVar5 + 0x3c;
      iVar2 = iVar2 + 1;
    } while (iVar2 < 10);
    if (DAT_803ddea4 != 0) {
      FUN_80095208();
    }
    iVar2 = 0;
    iVar5 = 0;
    do {
      pfVar4 = (float *)(DAT_803ddea0 + iVar5);
      if (*(char *)(pfVar4 + 6) != -1) {
        FUN_80259000(0xb8,2,1);
        DAT_cc008000 = *pfVar4 - FLOAT_803dda58;
        DAT_cc008000 = pfVar4[1];
        DAT_cc008000 = pfVar4[2] - FLOAT_803dda5c;
      }
      iVar5 = iVar5 + 0x1c;
      iVar2 = iVar2 + 1;
    } while (iVar2 < 0x1e);
    if (DAT_803ddeac != 0) {
      FUN_8007c7e0(DAT_803dde90);
    }
    iVar2 = 0;
    iVar5 = 0;
    iVar7 = 0;
    iVar6 = 0;
    do {
      puVar3 = (undefined4 *)(DAT_803ddea8 + iVar5);
      if ((*(short *)(puVar3 + 5) != 0) && (*(char *)(puVar3 + 6) == '\0')) {
        FUN_8005d294(uVar1,0xff,0xff,0xff,(char)*(short *)(puVar3 + 5));
        local_3c = *puVar3;
        local_38 = puVar3[1];
        local_34 = puVar3[2];
        local_40 = puVar3[4];
        local_48[0] = *(ushort *)((int)puVar3 + 0x16);
        local_48[2] = 0;
        local_48[1] = 0;
        FUN_8000e840((double)FLOAT_803dff6c,uVar1,(int)uVar9,local_48,(float *)0x0);
        FUN_8007d7ec();
        FUN_8005d108(DAT_803ddec4 + iVar6,DAT_803ddec0 + iVar7,2);
      }
      iVar5 = iVar5 + 0x1c;
      iVar7 = iVar7 + 0x20;
      iVar6 = iVar6 + 0x40;
      iVar2 = iVar2 + 1;
    } while (iVar2 < 0x1e);
    FUN_80054470();
  }
  FUN_80286884();
  return;
}

