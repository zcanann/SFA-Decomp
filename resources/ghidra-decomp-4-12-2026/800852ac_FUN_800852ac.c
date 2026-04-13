// Function: FUN_800852ac
// Entry: 800852ac
// Size: 824 bytes

void FUN_800852ac(undefined4 param_1,undefined4 param_2,uint param_3)

{
  int iVar1;
  int *piVar2;
  undefined4 uVar3;
  uint uVar4;
  undefined8 uVar5;
  
  uVar5 = FUN_80286840();
  if ((DAT_803ddd10 != 0) &&
     ((int)*(short *)((int)uVar5 + 0xb4) != (int)*(char *)((int)((ulonglong)uVar5 >> 0x20) + 0x57)))
  {
    (**(code **)(*DAT_803dd6e8 + 0x44))(0,0,0);
  }
  while ('\0' < DAT_803ddd93) {
    DAT_803ddd93 = DAT_803ddd93 + -1;
    iVar1 = DAT_803ddd93 * 8;
    uVar4 = (uint)*(short *)(&DAT_8039b220 + iVar1);
    uVar3 = *(undefined4 *)(&DAT_8039b21c + iVar1);
    switch((&DAT_8039b222)[iVar1]) {
    case 3:
      if ((param_3 & 0xff) == 0) {
        (**(code **)(*DAT_803dd708 + 8))(uVar3,uVar4,0,0x10000,0xffffffff,0);
      }
      break;
    case 4:
      if ((param_3 & 0xff) == 0) {
        FUN_80008b6c();
      }
      break;
    case 5:
      if (((param_3 & 0xff) == 0) &&
         (piVar2 = (int *)FUN_80013ee8(uVar4 + 0xab & 0xffff), piVar2 != (int *)0x0)) {
        (**(code **)(*piVar2 + 4))(uVar3,0,0,1,0xffffffff,uVar4 & 0xff,0);
        FUN_80013e4c((undefined *)piVar2);
      }
      break;
    case 9:
      if ((param_3 & 0xff) == 0) {
        switch(uVar4 & 0x2f) {
        case 6:
          (**(code **)(*DAT_803dd6cc + 8))((int)(uVar4 & 0xfc0) >> 4,3);
          break;
        case 7:
          (**(code **)(*DAT_803dd6cc + 0xc))((int)(uVar4 & 0xfc0) >> 4,3);
          break;
        case 8:
          (**(code **)(*DAT_803dd6cc + 8))((int)(uVar4 & 0xfc0) >> 4,2);
          break;
        case 9:
          (**(code **)(*DAT_803dd6cc + 0xc))((int)(uVar4 & 0xfc0) >> 4,2);
          break;
        case 0xb:
          (**(code **)(*DAT_803dd6cc + 8))((int)(uVar4 & 0xfc0) >> 4,4);
          break;
        case 0xc:
          (**(code **)(*DAT_803dd6cc + 0x10))((double)FLOAT_803dfca8,(int)(uVar4 & 0xfc0) >> 4,4);
        }
      }
      break;
    case 0xb:
      FUN_800201ac(uVar4,1);
      break;
    case 0xc:
      FUN_800201ac(uVar4,0);
      break;
    case 0xd:
      if ((param_3 & 0xff) == 0) {
        (**(code **)(*DAT_803dd6e8 + 0x44))(*(undefined4 *)(&DAT_8030f964 + uVar4 * 4),0,0);
        if (*(int *)(&DAT_8030f964 + uVar4 * 4) == -1) {
          DAT_803ddd10 = 0;
        }
        else {
          DAT_803ddd10 = 1;
        }
      }
    }
  }
  FUN_8028688c();
  return;
}

