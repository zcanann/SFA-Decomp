// Function: FUN_801d70d8
// Entry: 801d70d8
// Size: 912 bytes

void FUN_801d70d8(undefined4 param_1,undefined4 param_2,int param_3)

{
  bool bVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  int *piVar5;
  undefined4 uVar6;
  int *piVar7;
  
  iVar2 = FUN_802860dc();
  piVar7 = *(int **)(iVar2 + 0xb8);
  iVar3 = FUN_80080340(param_3);
  if (iVar3 == 0x35f) {
    FUN_80080360(param_3,0x2648);
    iVar3 = FUN_80014940();
    if (iVar3 != 0x10) {
      FUN_80014948(0x10);
    }
  }
  iVar3 = *piVar7;
  if (iVar3 != 0) {
    FUN_8002fa48((double)(*(float *)(iVar2 + 0x98) - *(float *)(iVar3 + 0x98)),
                 (double)FLOAT_803db414,iVar3,0);
  }
  *(code **)(param_3 + 0xec) = FUN_801d6d98;
  *(code **)(param_3 + 0xe8) = FUN_801d70b4;
  if (*(char *)(param_3 + 0x56) != '\0') {
    *(byte *)((int)piVar7 + 10) = *(byte *)((int)piVar7 + 10) & 0xfc;
    iVar3 = FUN_801d6d58();
    if (iVar3 != 0) {
      *(byte *)((int)piVar7 + 10) = *(byte *)((int)piVar7 + 10) | 1;
    }
    iVar3 = FUN_8001ffb4(0x2e8);
    if (iVar3 == 0) {
      iVar3 = FUN_8001ffb4(0x123);
      if (iVar3 == 0) {
        bVar1 = false;
      }
      else {
        bVar1 = true;
      }
    }
    else {
      bVar1 = true;
    }
    if (bVar1) {
      *(byte *)((int)piVar7 + 10) = *(byte *)((int)piVar7 + 10) | 2;
    }
    *(undefined *)(param_3 + 0x56) = 0;
    iVar3 = FUN_8001ffb4((int)*(short *)((int)piVar7 + 0xe));
    if ((iVar3 != 0) && (iVar3 = FUN_80080340(param_3), iVar3 == 0x35f)) {
      FUN_8000d0c0();
      FUN_800801e8();
      FUN_8000cf54(0);
      *(byte *)(param_3 + 0x90) = *(byte *)(param_3 + 0x90) | 4;
    }
  }
  iVar3 = 0;
  do {
    if ((int)(uint)*(byte *)(param_3 + 0x8b) <= iVar3) {
      FUN_801d6914(iVar2);
      FUN_80286128(0);
      return;
    }
    switch(*(undefined *)(param_3 + iVar3 + 0x81)) {
    case 3:
      *(undefined *)(piVar7 + 2) = 0;
      break;
    case 4:
      *(undefined *)(piVar7 + 2) = 1;
      break;
    case 6:
      FUN_8012fdcc(0);
      FUN_80014948(1);
      FUN_800552e8(0x7e,1);
      break;
    case 7:
      FUN_8012fdcc(0);
      FUN_80014948(1);
      FUN_800200e8(0x884,1);
      FUN_800552e8(0x7e,1);
      break;
    case 9:
      (**(code **)(*DAT_803dcaac + 0x44))(0x17,1);
      (**(code **)(*DAT_803dcaac + 0x44))(0xe,2);
      FUN_8012fdcc(0);
      FUN_80014948(1);
      break;
    case 10:
      *(byte *)((int)piVar7 + 9) = *(byte *)((int)piVar7 + 9) ^ 1;
      break;
    case 0xc:
      FUN_8012fdcc(0);
      FUN_80014948(1);
      FUN_800552e8(0x33,0);
      break;
    case 0xd:
      FUN_8001b700();
    case 0xe:
    case 0xf:
    case 0x10:
    case 0x11:
      iVar4 = FUN_80014940();
      if (iVar4 == 0x10) {
        piVar5 = (int *)FUN_80014938();
        (**(code **)(*piVar5 + 0x10))(*(byte *)(param_3 + iVar3 + 0x81) - 0xd);
      }
      FUN_800200e8((int)*(short *)((int)piVar7 + 0xe),1);
      FUN_800200e8(0x887,1);
      break;
    case 0x12:
      (**(code **)(*DAT_803dcaac + 0x50))(7,10,0);
      break;
    case 0x14:
      FUN_8004350c(0,0,1);
      break;
    case 0x15:
      FUN_8004350c(0,0,1);
      uVar6 = FUN_800481b0(0x42);
      FUN_800437bc(uVar6,0x20000000);
      break;
    case 0x16:
      FUN_8004350c(0,0,1);
      uVar6 = FUN_800481b0(0x42);
      FUN_800437bc(uVar6,0x20000000);
      break;
    case 0x17:
      *(byte *)(piVar7 + 0x35) = *(byte *)(piVar7 + 0x35) | 4;
      FUN_8000bb18(0,0x420);
    }
    iVar3 = iVar3 + 1;
  } while( true );
}

