// Function: FUN_8022578c
// Entry: 8022578c
// Size: 1100 bytes

void FUN_8022578c(undefined4 param_1,float *param_2)

{
  byte bVar1;
  short *psVar2;
  int iVar3;
  
  if ((*(ushort *)((int)param_2 + 0x1a) & 2) != 0) {
    return;
  }
  *(undefined *)((int)param_2 + 0xd) = *(undefined *)(param_2 + 3);
  bVar1 = *(byte *)(param_2 + 3);
  if (bVar1 == 3) {
    iVar3 = FUN_8001ffb4(0xcac);
    if (iVar3 != 0) {
      FUN_800200e8(0xda9,0);
      FUN_800200e8(0xc37,1);
      psVar2 = (short *)FUN_8002b9ec();
      (**(code **)(*DAT_803dcaac + 0x1c))(psVar2 + 6,(int)*psVar2,1,0);
      *(undefined *)(param_2 + 3) = 7;
    }
    goto LAB_80225bb0;
  }
  if (bVar1 < 3) {
    if (bVar1 == 1) {
      if ((*(ushort *)((int)param_2 + 0x1a) & 1) == 0) {
        iVar3 = FUN_8001ffb4(0x7f9);
        if (iVar3 == 0) {
          iVar3 = FUN_80014670();
          if (iVar3 != 0) {
            FUN_800200e8(0x7ef,0);
            FUN_800200e8(0x7ed,0);
            FUN_800200e8(0xba6,0);
            FUN_800200e8(0xedd,0);
            *(undefined *)(param_2 + 3) = 0;
          }
        }
        else {
          *(ushort *)((int)param_2 + 0x1a) = *(ushort *)((int)param_2 + 0x1a) | 4;
          FUN_8001467c();
          iVar3 = FUN_8001ffb4(0x7fa);
          if (iVar3 == 0) {
            FUN_8000bb18(0,0x109);
          }
          else {
            FUN_8000bb18(0,0x7e);
          }
          FUN_800200e8(0xba6,0);
          FUN_800200e8(0xedd,0);
          iVar3 = FUN_8001ffb4(0x7fa);
          if (iVar3 == 0) {
            (**(code **)(*DAT_803dca54 + 0x48))(1,param_1,0xffffffff);
            *(undefined *)(param_2 + 3) = 0;
          }
          else {
            (**(code **)(*DAT_803dca54 + 0x48))(0,param_1,0xffffffff);
            *(undefined *)(param_2 + 3) = 3;
          }
          *(ushort *)((int)param_2 + 0x1a) = *(ushort *)((int)param_2 + 0x1a) | 2;
        }
      }
      else {
        FUN_800146bc(0x1d,0x3c);
        FUN_8001469c();
        FUN_800200e8(0xba6,1);
        FUN_800200e8(0xedd,1);
      }
      goto LAB_80225bb0;
    }
    if (bVar1 != 0) {
      if ((*(ushort *)((int)param_2 + 0x1a) & 1) == 0) {
        iVar3 = FUN_8001ffb4(0x7fa);
        if (iVar3 == 0) {
          iVar3 = FUN_80014670();
          if (iVar3 != 0) {
            FUN_800200e8(0x7f0,0);
            FUN_800200e8(0x7ee,0);
            FUN_800200e8(0xba6,0);
            FUN_800200e8(0xedc,0);
            *(undefined *)(param_2 + 3) = 0;
          }
        }
        else {
          *(ushort *)((int)param_2 + 0x1a) = *(ushort *)((int)param_2 + 0x1a) | 8;
          FUN_8001467c();
          iVar3 = FUN_8001ffb4(0x7f9);
          if (iVar3 == 0) {
            FUN_8000bb18(0,0x109);
          }
          else {
            FUN_8000bb18(0,0x7e);
          }
          FUN_800200e8(0xba6,0);
          FUN_800200e8(0xedc,0);
          iVar3 = FUN_8001ffb4(0x7f9);
          if (iVar3 == 0) {
            (**(code **)(*DAT_803dca54 + 0x48))(1,param_1,0xffffffff);
            *(undefined *)(param_2 + 3) = 0;
          }
          else {
            (**(code **)(*DAT_803dca54 + 0x48))(0,param_1,0xffffffff);
            *(undefined *)(param_2 + 3) = 3;
          }
          *(ushort *)((int)param_2 + 0x1a) = *(ushort *)((int)param_2 + 0x1a) | 2;
        }
      }
      else {
        FUN_800146bc(0x1d,0x50);
        FUN_8001469c();
        FUN_800200e8(0xba6,1);
        FUN_800200e8(0xedc,1);
      }
      goto LAB_80225bb0;
    }
  }
  else if (bVar1 == 7) goto LAB_80225bb0;
  if (((*(ushort *)((int)param_2 + 0x1a) & 4) == 0) && (iVar3 = FUN_8001ffb4(0x7ed), iVar3 != 0)) {
    FUN_800200e8(0x7ef,1);
    *param_2 = FLOAT_803e6db0;
    *(undefined *)(param_2 + 3) = 1;
    *(ushort *)((int)param_2 + 0x1a) = *(ushort *)((int)param_2 + 0x1a) | 2;
  }
  else if (((*(ushort *)((int)param_2 + 0x1a) & 8) == 0) &&
          (iVar3 = FUN_8001ffb4(0x7ee), iVar3 != 0)) {
    FUN_800200e8(0x7f0,1);
    *param_2 = FLOAT_803e6db0;
    *(undefined *)(param_2 + 3) = 2;
    *(ushort *)((int)param_2 + 0x1a) = *(ushort *)((int)param_2 + 0x1a) | 2;
  }
LAB_80225bb0:
  *(ushort *)((int)param_2 + 0x1a) = *(ushort *)((int)param_2 + 0x1a) & 0xfffe;
  return;
}

