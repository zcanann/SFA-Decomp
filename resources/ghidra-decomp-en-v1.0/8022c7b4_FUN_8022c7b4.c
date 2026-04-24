// Function: FUN_8022c7b4
// Entry: 8022c7b4
// Size: 1592 bytes

undefined4 FUN_8022c7b4(short *param_1,undefined4 param_2,int param_3)

{
  ushort uVar1;
  short *psVar2;
  char cVar5;
  int iVar3;
  undefined4 uVar4;
  int iVar6;
  int iVar7;
  
  iVar6 = *(int *)(param_1 + 0x5c);
  FUN_8000faac();
  *(undefined **)(param_3 + 0xe8) = &LAB_8022c7a4;
  if ((*(byte *)(iVar6 + 0x477) & 1) == 0) {
    FUN_8022cdec(param_1,iVar6);
  }
  else {
    FUN_8022c30c(param_1,iVar6);
    FUN_8022a9c8(param_1,iVar6);
    if (*(int *)(iVar6 + 0x10) != 0) {
      FUN_8022f148(*(int *)(iVar6 + 0x10),0,0);
    }
    *(ushort *)(*(int *)(iVar6 + 0x418) + 6) = *(ushort *)(*(int *)(iVar6 + 0x418) + 6) | 0x4000;
    *(undefined *)(*(int *)(iVar6 + 0x418) + 0x36) = 0;
    *(ushort *)(*(int *)(iVar6 + 0x41c) + 6) = *(ushort *)(*(int *)(iVar6 + 0x41c) + 6) | 0x4000;
    *(undefined *)(*(int *)(iVar6 + 0x41c) + 0x36) = 0;
    param_1[3] = param_1[3] & 0xbfff;
    for (iVar7 = 0; iVar7 < (int)(uint)*(byte *)(param_3 + 0x8b); iVar7 = iVar7 + 1) {
      switch(*(undefined *)(param_3 + iVar7 + 0x81)) {
      case 1:
        FUN_80043034();
        FUN_800552e8(0x60,0);
        break;
      case 2:
        FUN_80043034();
        FUN_8022c680(param_1);
        break;
      case 4:
        FUN_8004350c(0,0,1);
        FUN_800437bc(0,0x80000000);
        FUN_80043074();
        break;
      case 5:
        if ((*(char *)(iVar6 + 0x47b) == '\0') && (iVar3 = FUN_8001ffb4(0xc85), iVar3 != 0)) {
          FUN_80042f78(0xb);
          uVar4 = FUN_800481b0(0xb);
          FUN_80043560(uVar4,0);
        }
        else {
          FUN_80042f78((&DAT_803dc3c8)[*(byte *)(iVar6 + 0x47b)]);
          uVar4 = FUN_800481b0((&DAT_803dc3c8)[*(byte *)(iVar6 + 0x47b)]);
          FUN_80043560(uVar4,0);
        }
        cVar5 = *(char *)(param_1 + 0x56);
        if (cVar5 == '<') {
          FUN_800200e8(0x458,0);
          FUN_800200e8(0x47c,0);
          FUN_800200e8(0x4a3,0);
          (**(code **)(*DAT_803dcaac + 0x50))(0xc,0,1);
          FUN_800200e8(0xd73,0);
        }
        else if (cVar5 < '<') {
          if ((cVar5 != ':') && ('9' < cVar5)) {
            (**(code **)(*DAT_803dcaac + 0x50))(0x13,0,1);
            (**(code **)(*DAT_803dcaac + 0x50))(0x13,0x16,1);
          }
        }
        else if (cVar5 == '>') {
          FUN_800200e8(0x5db,0);
          (**(code **)(*DAT_803dcaac + 0x50))(2,0xf,1);
          (**(code **)(*DAT_803dcaac + 0x50))(2,0x10,1);
          FUN_800200e8(0xe7b,0);
          FUN_800200e8(0x9e9,0);
        }
        else if (cVar5 < '>') {
          FUN_800200e8(0x36a,0);
          (**(code **)(*DAT_803dcaac + 0x50))(0xd,0,1);
          (**(code **)(*DAT_803dcaac + 0x50))(0xd,1,1);
          (**(code **)(*DAT_803dcaac + 0x50))(0xd,5,1);
          (**(code **)(*DAT_803dcaac + 0x50))(0xd,10,1);
          (**(code **)(*DAT_803dcaac + 0x50))(0xd,0xb,1);
          FUN_800200e8(0xe05,0);
        }
        break;
      case 6:
        FUN_8004350c(0,0,1);
        FUN_80042f78(0x29);
        uVar4 = FUN_800481b0(0x29);
        FUN_80043560(uVar4,0);
        break;
      case 7:
        if (-1 < *(char *)(iVar6 + 0x339)) {
          iVar3 = *(int *)(param_1 + 0x5c);
          *(short *)(iVar3 + 0x47c) = *(short *)(iVar3 + 0x47c) + 200;
          uVar1 = *(ushort *)(iVar3 + 0x47c);
          if (9999 < uVar1) {
            uVar1 = 9999;
          }
          *(ushort *)(iVar3 + 0x47c) = uVar1;
        }
        FUN_80129698((int)*(char *)(iVar6 + 0x47e),*(undefined2 *)(iVar6 + 0x47c),
                     *(undefined *)(iVar6 + 0x470),2);
        break;
      case 8:
        psVar2 = (short *)FUN_8000faac();
        *(float *)(iVar6 + 0x484) = *(float *)(psVar2 + 6) - *(float *)(param_1 + 6);
        *(float *)(iVar6 + 0x488) = *(float *)(psVar2 + 8) - *(float *)(param_1 + 8);
        *(float *)(iVar6 + 0x48c) = *(float *)(psVar2 + 10) - *(float *)(param_1 + 10);
        *(short *)(iVar6 + 0x490) = *param_1 - *psVar2;
        if (0x8000 < *(short *)(iVar6 + 0x490)) {
          *(short *)(iVar6 + 0x490) = *(short *)(iVar6 + 0x490) + 1;
        }
        if (*(short *)(iVar6 + 0x490) < -0x8000) {
          *(short *)(iVar6 + 0x490) = *(short *)(iVar6 + 0x490) + -1;
        }
        *(short *)(iVar6 + 0x492) = param_1[1] - psVar2[1];
        if (0x8000 < *(short *)(iVar6 + 0x492)) {
          *(short *)(iVar6 + 0x492) = *(short *)(iVar6 + 0x492) + 1;
        }
        if (*(short *)(iVar6 + 0x492) < -0x8000) {
          *(short *)(iVar6 + 0x492) = *(short *)(iVar6 + 0x492) + -1;
        }
        *(short *)(iVar6 + 0x494) = psVar2[2] - param_1[2];
        *(undefined *)(iVar6 + 0x47f) = 1;
        break;
      case 9:
        *(undefined *)(iVar6 + 0x47f) = 0;
        break;
      case 10:
        cVar5 = FUN_8002e04c();
        if (cVar5 != '\0') {
          iVar3 = FUN_8002bdf4(0x24,0x608);
          *(undefined4 *)(iVar3 + 8) = *(undefined4 *)(param_1 + 6);
          *(undefined4 *)(iVar3 + 0xc) = *(undefined4 *)(param_1 + 8);
          *(undefined4 *)(iVar3 + 0x10) = *(undefined4 *)(param_1 + 10);
          *(undefined *)(iVar3 + 4) = 1;
          *(undefined *)(iVar3 + 5) = 1;
          iVar3 = FUN_8002b5a0(param_1);
          if (iVar3 != 0) {
            FUN_8022f558(iVar3,300);
          }
        }
        break;
      case 0xb:
        *(undefined *)(iVar6 + 0x44c) = 1;
        FUN_8022b764(param_1,iVar6,*(undefined *)(iVar6 + 0x43d));
        *(byte *)(iVar6 + 0x43d) = *(byte *)(iVar6 + 0x43d) ^ 1;
        break;
      case 0xc:
        FUN_8022b998(param_1,iVar6,0,1,1);
        FUN_8022b998(param_1,iVar6,1,1,0);
        break;
      case 0xd:
        FUN_80125ba4(0x13);
        break;
      case 0xe:
        FUN_80125ba4(0x14);
      }
    }
  }
  return 0;
}

