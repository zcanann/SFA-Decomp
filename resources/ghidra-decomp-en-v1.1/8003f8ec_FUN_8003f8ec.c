// Function: FUN_8003f8ec
// Entry: 8003f8ec
// Size: 1132 bytes

void FUN_8003f8ec(undefined4 param_1,undefined4 param_2,int param_3)

{
  ushort *puVar1;
  int *piVar2;
  float *pfVar3;
  code *pcVar4;
  char cVar8;
  uint uVar5;
  int iVar6;
  undefined4 *puVar7;
  int iVar9;
  uint local_a8;
  undefined4 uStack_a4;
  undefined4 local_a0;
  int local_9c [4];
  int local_8c;
  float afStack_88 [12];
  float afStack_58 [22];
  
  puVar1 = (ushort *)FUN_80286840();
  piVar2 = (int *)FUN_8002b660((int)puVar1);
  if (DAT_803dd8a4 == (float *)0x0) {
    FUN_8002b554(puVar1,afStack_58,'\0');
  }
  else {
    FUN_802475e4(DAT_803dd8a4,afStack_58);
    DAT_803dd8a4 = (float *)0x0;
  }
  pfVar3 = (float *)FUN_8000f56c();
  FUN_80247618(pfVar3,afStack_58,afStack_88);
  if ((*(ushort *)(piVar2 + 6) & 8) == 0) {
    *(undefined *)(piVar2 + 0x18) = 0;
    if (((*(short *)(param_3 + 0xec) == 0) || ((*(ushort *)(param_3 + 2) & 2) != 0)) ||
       (*(char *)(param_3 + 0xf3) == '\0')) {
      FUN_8002861c((int)piVar2);
      pfVar3 = (float *)FUN_80028630(piVar2,0);
      FUN_802475e4((float *)&DAT_802cbac0,pfVar3);
      DAT_803dd8c8 = 3;
    }
    else if (DAT_803dd8b0 == param_3) {
      DAT_803dd8c8 = 1;
    }
    else {
      FUN_80028c18(piVar2,param_3,(int)puVar1,&DAT_802cbac0);
      FUN_8003c270(param_3,piVar2);
    }
    iVar9 = *(int *)(puVar1 + 0x2a);
    if (iVar9 != 0) {
      *(char *)(iVar9 + 0xaf) = *(char *)(iVar9 + 0xaf) + -1;
      if (*(char *)(*(int *)(puVar1 + 0x2a) + 0xaf) < '\0') {
        *(undefined *)(*(int *)(puVar1 + 0x2a) + 0xaf) = 0;
      }
    }
    *(ushort *)(piVar2 + 6) = *(ushort *)(piVar2 + 6) | 8;
  }
  uVar5 = (uint)*(ushort *)(param_3 + 0xd8) << 3;
  FUN_80013a84(local_9c,*(undefined4 *)(param_3 + 0xd4),uVar5,uVar5);
  if ((*(ushort *)(param_3 + 0xe2) & 2) == 0) {
    local_a0 = -0x100;
  }
  else if (DAT_803dd8a8 == '\0') {
    FUN_80089ab8((uint)*(byte *)(puVar1 + 0x79),(byte *)&local_a0,(byte *)((int)&local_a0 + 1),
                 (byte *)((int)&local_a0 + 2));
  }
  else {
    local_a0 = (uint)CONCAT21(CONCAT11(DAT_803dd8d8,uRam803dd8d9),uRam803dd8da) << 8;
    DAT_803dd8a8 = '\0';
  }
  local_a0 = CONCAT31(local_a0._0_3_,*(undefined *)((int)puVar1 + 0x37));
  pcVar4 = (code *)FUN_800285f8((int)piVar2);
  if ((DAT_803dd8aa == '\0') || (pcVar4 != (code *)0x0)) {
    FUN_8000fb20();
    if ((pcVar4 == (code *)0x0) || (cVar8 = (*pcVar4)(puVar1,piVar2,0), cVar8 == '\0')) {
      FUN_80070540();
      FUN_80052a6c();
      uVar5 = FUN_8005383c(*(uint *)(*(int *)(param_3 + 0x38) + 0x24));
      FUN_80052134(uVar5,0,0,(char *)&local_a0,0,0);
      cVar8 = FUN_8004c3c4();
      if (cVar8 != '\0') {
        FUN_80070658((undefined *)&uStack_a4);
        FUN_8004e974(&uStack_a4);
      }
      FUN_80052a38();
      FUN_8025a608(4,0,0,0,0,0,2);
      FUN_8025a608(5,0,0,0,0,0,2);
      FUN_8025a5bc(0);
      DAT_803dd8aa = '\x01';
      DAT_803dc0e4 = local_a0;
    }
  }
  else {
    uVar5 = FUN_8005383c(*(uint *)(*(int *)(param_3 + 0x38) + 0x24));
    if (DAT_803dd8ac != uVar5) {
      DAT_803dd8ac = uVar5;
      FUN_8004c460(uVar5,0);
    }
    if (((DAT_803dc0e4._0_1_ != local_a0._0_1_) || (DAT_803dc0e4._1_1_ != local_a0._1_1_)) ||
       ((DAT_803dc0e4._2_1_ != local_a0._2_1_ || ((DAT_803dc0e4 & 0xff) != (local_a0 & 0xff))))) {
      local_a8 = local_a0;
      FUN_8025c510(0,(byte *)&local_a8);
      DAT_803dc0e4 = local_a0;
    }
  }
  if (DAT_803dd8b0 != param_3) {
    FUN_802585d8(9,piVar2[(*(ushort *)(piVar2 + 6) >> 1 & 1) + 7],6);
    FUN_802585d8(0xd,*(uint *)(param_3 + 0x34),4);
    DAT_803dd8b0 = param_3;
  }
  FUN_8003f6a4(puVar1,param_3,*(int *)(param_3 + 0x38));
  local_8c = local_8c + 4;
  FUN_8003e58c(param_3,*(undefined4 *)(param_3 + 0x38),local_9c);
  local_8c = local_8c + 4;
  FUN_8003e158(param_3,piVar2,local_9c,afStack_88);
  uVar5 = local_8c + 4;
  iVar9 = (int)uVar5 >> 3;
  iVar6 = local_9c[0] + iVar9;
  local_8c = local_8c + 0xc;
  puVar7 = (undefined4 *)
           FUN_80028438(param_3,(uint3)(CONCAT12(*(undefined *)(iVar6 + 2),
                                                 CONCAT11(*(undefined *)(iVar6 + 1),
                                                          *(undefined *)(local_9c[0] + iVar9))) >>
                                       (uVar5 & 7)) & 0xff);
  FUN_8025d63c(*puVar7,(uint)*(ushort *)(puVar7 + 1));
  FUN_8028688c();
  return;
}

