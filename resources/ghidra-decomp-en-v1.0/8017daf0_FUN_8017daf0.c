// Function: FUN_8017daf0
// Entry: 8017daf0
// Size: 356 bytes

void FUN_8017daf0(int param_1)

{
  int iVar1;
  int iVar2;
  int iVar3;
  double dVar4;
  
  iVar3 = *(int *)(param_1 + 0xb8);
  iVar1 = FUN_8002b9ec();
  dVar4 = (double)FUN_80021690(iVar1 + 0x18,param_1 + 0x18);
  if ((dVar4 < (double)FLOAT_803e37ec) &&
     (dVar4 = (double)FUN_80021704(iVar1 + 0x18,param_1 + 0x18), dVar4 < (double)FLOAT_803e37f0)) {
    iVar2 = FUN_8001ffb4(0x90f);
    if (iVar2 == 0) {
      (**(code **)(*DAT_803dca54 + 0x7c))(0x444,0,0);
      *(undefined2 *)(iVar3 + 0x5c) = 0xffff;
      *(undefined2 *)(iVar3 + 0x5e) = 0;
      *(float *)(iVar3 + 0x60) = FLOAT_803e37c8;
      FUN_800378c4(iVar1,0x7000a,param_1,iVar3 + 0x5c);
      FUN_800200e8(0x90f,1);
      *(byte *)(iVar3 + 0x5a) = *(byte *)(iVar3 + 0x5a) | 4;
    }
    else {
      FUN_80296afc(iVar1,*(undefined2 *)(iVar3 + 0x38));
      FUN_800999b4((double)FLOAT_803e37c8,param_1,0xff,0x28);
      FUN_8000bb18(param_1,0x58);
      iVar1 = *(int *)(param_1 + 0xb8);
      if ((*(ushort *)(param_1 + 6) & 0x2000) == 0) {
        if (*(int *)(param_1 + 0x54) != 0) {
          FUN_80035f00(param_1);
        }
        *(byte *)(iVar1 + 0x5a) = *(byte *)(iVar1 + 0x5a) | 2;
      }
      else {
        FUN_8002cbc4(param_1);
      }
    }
  }
  return;
}

