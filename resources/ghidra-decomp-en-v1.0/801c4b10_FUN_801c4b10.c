// Function: FUN_801c4b10
// Entry: 801c4b10
// Size: 616 bytes

void FUN_801c4b10(undefined4 param_1,undefined4 param_2,int param_3)

{
  int iVar1;
  undefined4 uVar2;
  char cVar3;
  int iVar4;
  int *piVar5;
  
  iVar1 = FUN_802860d8();
  piVar5 = *(int **)(iVar1 + 0xb8);
  uVar2 = FUN_8002b9ec();
  *(undefined2 *)(param_3 + 0x70) = 0xffff;
  *(undefined *)(param_3 + 0x56) = 0;
  for (iVar4 = 0; iVar4 < (int)(uint)*(byte *)(param_3 + 0x8b); iVar4 = iVar4 + 1) {
    switch(*(undefined *)(param_3 + iVar4 + 0x81)) {
    case 1:
      piVar5[6] = piVar5[6] | 2;
      break;
    case 2:
      piVar5[6] = piVar5[6] & 0xfffffffd;
      if ((piVar5[6] & 0x20U) != 0) {
        FUN_8011f6d4(0);
        piVar5[6] = piVar5[6] & 0xffffffdf;
      }
      break;
    case 3:
      piVar5[4] = (int)FLOAT_803e4f54;
      break;
    case 4:
      piVar5[4] = (int)FLOAT_803e4f58;
      break;
    case 5:
      piVar5[4] = (int)-(float)piVar5[4];
      piVar5[3] = (int)-(float)piVar5[4];
      break;
    case 6:
      piVar5[4] = (int)((float)piVar5[4] * FLOAT_803e4f5c);
      break;
    case 7:
      FUN_80296518(uVar2,4,1);
      FUN_800200e8(0x12a,1);
      FUN_800200e8(0xff,1);
      (**(code **)(*DAT_803dcaac + 0x44))(0xb,3);
      break;
    case 8:
      piVar5[4] = (int)((float)piVar5[4] * FLOAT_803e4f60);
      break;
    case 0xe:
      *(ushort *)(iVar1 + 6) = *(ushort *)(iVar1 + 6) | 0x4000;
      if (*piVar5 != 0) {
        FUN_8001db6c((double)FLOAT_803e4f50,*piVar5,0);
      }
      break;
    case 0xf:
      *(ushort *)(iVar1 + 6) = *(ushort *)(iVar1 + 6) & 0xbfff;
      if (*piVar5 != 0) {
        FUN_8001db6c((double)FLOAT_803e4f50,*piVar5,0);
      }
    }
    *(undefined *)(param_3 + iVar4 + 0x81) = 0;
  }
  if (((piVar5[6] & 2U) == 0) || (cVar3 = FUN_801c49b8(iVar1), cVar3 == '\0')) {
    piVar5[6] = piVar5[6] | 1;
    uVar2 = 0;
  }
  else {
    FUN_8011f6d4(0);
    piVar5[6] = piVar5[6] & 0xffffffdd;
    *(undefined *)(piVar5 + 9) = 3;
    FUN_800200e8(0xe82,0);
    FUN_800200e8(0xe83,0);
    FUN_800200e8(0xe84,0);
    FUN_800200e8(0xe85,0);
    uVar2 = 4;
  }
  FUN_80286124(uVar2);
  return;
}

