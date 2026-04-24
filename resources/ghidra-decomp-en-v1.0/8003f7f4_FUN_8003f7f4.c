// Function: FUN_8003f7f4
// Entry: 8003f7f4
// Size: 1132 bytes

/* WARNING: Could not reconcile some variable overlaps */

void FUN_8003f7f4(undefined4 param_1,undefined4 param_2,int param_3,undefined4 param_4)

{
  int iVar1;
  int iVar2;
  undefined4 uVar3;
  code *pcVar4;
  char cVar6;
  undefined4 *puVar5;
  int iVar7;
  uint uVar8;
  uint local_a8;
  undefined auStack164 [4];
  undefined4 local_a0;
  int local_9c [4];
  int local_8c;
  undefined auStack136 [48];
  undefined auStack88 [88];
  
  iVar1 = FUN_802860dc();
  iVar2 = FUN_8002b588();
  if (DAT_803dcc24 == 0) {
    FUN_8002b47c(iVar1,auStack88,0);
  }
  else {
    FUN_80246e80(DAT_803dcc24,auStack88);
    DAT_803dcc24 = 0;
  }
  uVar3 = FUN_8000f54c();
  FUN_80246eb4(uVar3,auStack88,auStack136);
  if ((*(ushort *)(iVar2 + 0x18) & 8) == 0) {
    *(undefined *)(iVar2 + 0x60) = 0;
    if (((*(short *)(param_3 + 0xec) == 0) || ((*(ushort *)(param_3 + 2) & 2) != 0)) ||
       (*(char *)(param_3 + 0xf3) == '\0')) {
      FUN_80028558(iVar2);
      uVar3 = FUN_8002856c(iVar2,0);
      FUN_80246e80(&DAT_802caee8,uVar3);
      DAT_803dcc48 = 3;
    }
    else if (DAT_803dcc30 == param_3) {
      DAT_803dcc48 = 1;
    }
    else {
      FUN_80028b54(iVar2,param_3,iVar1,&DAT_802caee8);
      FUN_8003c178(param_3,iVar2);
    }
    iVar7 = *(int *)(iVar1 + 0x54);
    if (iVar7 != 0) {
      *(char *)(iVar7 + 0xaf) = *(char *)(iVar7 + 0xaf) + -1;
      if (*(char *)(*(int *)(iVar1 + 0x54) + 0xaf) < '\0') {
        *(undefined *)(*(int *)(iVar1 + 0x54) + 0xaf) = 0;
      }
    }
    *(ushort *)(iVar2 + 0x18) = *(ushort *)(iVar2 + 0x18) | 8;
  }
  iVar7 = (uint)*(ushort *)(param_3 + 0xd8) << 3;
  FUN_80013a64(local_9c,*(undefined4 *)(param_3 + 0xd4),iVar7,iVar7);
  if ((*(ushort *)(param_3 + 0xe2) & 2) == 0) {
    local_a0 = 0xffffff00;
  }
  else if (DAT_803dcc28 == '\0') {
    FUN_8008982c(*(undefined *)(iVar1 + 0xf2),&local_a0,(int)&local_a0 + 1,(int)&local_a0 + 2);
  }
  else {
    local_a0 = (uint)CONCAT21(CONCAT11(DAT_803dcc58,uRam803dcc59),uRam803dcc5a) << 8;
    DAT_803dcc28 = '\0';
  }
  local_a0 = local_a0 & 0xffffff00 | (uint)*(byte *)(iVar1 + 0x37);
  pcVar4 = (code *)FUN_80028534(iVar2);
  if ((DAT_803dcc2a == '\0') || (pcVar4 != (code *)0x0)) {
    FUN_8000fb00();
    if ((pcVar4 == (code *)0x0) || (cVar6 = (*pcVar4)(iVar1,iVar2,0), cVar6 == '\0')) {
      FUN_800703c4();
      FUN_800528f0();
      uVar3 = FUN_800536c0(*(undefined4 *)(*(int *)(param_3 + 0x38) + 0x24));
      FUN_80051fb8(uVar3,0,0,&local_a0,0,0);
      cVar6 = FUN_8004c248();
      if (cVar6 != '\0') {
        FUN_800704dc(auStack164);
        FUN_8004e7f8(auStack164);
      }
      FUN_800528bc();
      FUN_80259ea4(4,0,0,0,0,0,2);
      FUN_80259ea4(5,0,0,0,0,0,2);
      FUN_80259e58(0);
      DAT_803dcc2a = '\x01';
      DAT_803db484 = local_a0;
    }
  }
  else {
    iVar7 = FUN_800536c0(*(undefined4 *)(*(int *)(param_3 + 0x38) + 0x24));
    if (DAT_803dcc2c != iVar7) {
      DAT_803dcc2c = iVar7;
      FUN_8004c2e4(iVar7,0);
    }
    if (((DAT_803db484._0_1_ != local_a0._0_1_) || (DAT_803db484._1_1_ != local_a0._1_1_)) ||
       ((DAT_803db484._2_1_ != local_a0._2_1_ || ((DAT_803db484 & 0xff) != (local_a0 & 0xff))))) {
      local_a8 = local_a0;
      FUN_8025bdac(0,&local_a8);
      DAT_803db484 = local_a0;
    }
  }
  if (DAT_803dcc30 != param_3) {
    FUN_80257e74(9,*(undefined4 *)(iVar2 + (*(ushort *)(iVar2 + 0x18) >> 1 & 1) * 4 + 0x1c),6);
    FUN_80257e74(0xd,*(undefined4 *)(param_3 + 0x34),4);
    DAT_803dcc30 = param_3;
  }
  FUN_8003f5ac(iVar1,param_3,*(undefined4 *)(param_3 + 0x38));
  local_8c = local_8c + 4;
  FUN_8003e494(param_3,*(undefined4 *)(param_3 + 0x38),local_9c,param_4);
  local_8c = local_8c + 4;
  FUN_8003e060(param_3,iVar2,local_9c,auStack136);
  uVar8 = local_8c + 4;
  iVar1 = (int)uVar8 >> 3;
  iVar2 = local_9c[0] + iVar1;
  local_8c = local_8c + 0xc;
  puVar5 = (undefined4 *)
           FUN_80028374(param_3,CONCAT12(*(undefined *)(iVar2 + 2),
                                         CONCAT11(*(undefined *)(iVar2 + 1),
                                                  *(undefined *)(local_9c[0] + iVar1))) >>
                                (uVar8 & 7) & 0xff);
  FUN_8025ced8(*puVar5,*(undefined2 *)(puVar5 + 1));
  FUN_80286128();
  return;
}

