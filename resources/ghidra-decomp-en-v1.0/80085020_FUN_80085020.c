// Function: FUN_80085020
// Entry: 80085020
// Size: 824 bytes

void FUN_80085020(undefined4 param_1,undefined4 param_2,uint param_3)

{
  int iVar1;
  int *piVar2;
  undefined4 uVar3;
  uint uVar4;
  undefined8 uVar5;
  
  uVar5 = FUN_802860dc();
  if ((DAT_803dd090 != 0) &&
     ((int)*(short *)((int)uVar5 + 0xb4) != (int)*(char *)((int)((ulonglong)uVar5 >> 0x20) + 0x57)))
  {
    (**(code **)(*DAT_803dca68 + 0x44))(0,0,0);
  }
  while ('\0' < DAT_803dd113) {
    DAT_803dd113 = DAT_803dd113 + -1;
    iVar1 = DAT_803dd113 * 8;
    uVar4 = (uint)*(short *)(&DAT_8039a5c0 + iVar1);
    uVar3 = *(undefined4 *)(&DAT_8039a5bc + iVar1);
    switch((&DAT_8039a5c2)[iVar1]) {
    case 3:
      if ((param_3 & 0xff) == 0) {
        (**(code **)(*DAT_803dca88 + 8))(uVar3,uVar4,0,0x10000,0xffffffff,0);
      }
      break;
    case 4:
      if ((param_3 & 0xff) == 0) {
        FUN_80008b6c(uVar3,0,0,1,0xffffffff,uVar4 & 0xff,0);
      }
      break;
    case 5:
      if (((param_3 & 0xff) == 0) &&
         (piVar2 = (int *)FUN_80013ec8(uVar4 + 0xab & 0xffff,1), piVar2 != (int *)0x0)) {
        (**(code **)(*piVar2 + 4))(uVar3,0,0,1,0xffffffff,uVar4 & 0xff,0);
        FUN_80013e2c(piVar2);
      }
      break;
    case 9:
      if ((param_3 & 0xff) == 0) {
        switch(uVar4 & 0x2f) {
        case 6:
          (**(code **)(*DAT_803dca4c + 8))((int)(uVar4 & 0xfc0) >> 4,3);
          break;
        case 7:
          (**(code **)(*DAT_803dca4c + 0xc))((int)(uVar4 & 0xfc0) >> 4,3);
          break;
        case 8:
          (**(code **)(*DAT_803dca4c + 8))((int)(uVar4 & 0xfc0) >> 4,2);
          break;
        case 9:
          (**(code **)(*DAT_803dca4c + 0xc))((int)(uVar4 & 0xfc0) >> 4,2);
          break;
        case 0xb:
          (**(code **)(*DAT_803dca4c + 8))((int)(uVar4 & 0xfc0) >> 4,4);
          break;
        case 0xc:
          (**(code **)(*DAT_803dca4c + 0x10))((double)FLOAT_803df028,(int)(uVar4 & 0xfc0) >> 4,4);
        }
      }
      break;
    case 0xb:
      FUN_800200e8(uVar4,1);
      break;
    case 0xc:
      FUN_800200e8(uVar4,0);
      break;
    case 0xd:
      if ((param_3 & 0xff) == 0) {
        (**(code **)(*DAT_803dca68 + 0x44))(*(undefined4 *)(&DAT_8030eda4 + uVar4 * 4),0,0);
        if (*(int *)(&DAT_8030eda4 + uVar4 * 4) == -1) {
          DAT_803dd090 = 0;
        }
        else {
          DAT_803dd090 = 1;
        }
      }
    }
  }
  FUN_80286128();
  return;
}

