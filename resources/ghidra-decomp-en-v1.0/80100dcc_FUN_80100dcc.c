// Function: FUN_80100dcc
// Entry: 80100dcc
// Size: 468 bytes

undefined4 FUN_80100dcc(int param_1,undefined4 *param_2,undefined4 param_3)

{
  float fVar1;
  int iVar2;
  undefined4 uVar3;
  byte bVar4;
  undefined local_18;
  undefined local_17;
  undefined local_16;
  undefined local_15;
  
  iVar2 = FUN_80028424(*param_2,param_3);
  fVar1 = *(float *)(DAT_803dd524 + 0x134);
  if (FLOAT_803e1630 < fVar1) {
    if (FLOAT_803e1634 < fVar1) {
      if (FLOAT_803e1638 < fVar1) {
        if (FLOAT_803e163c < fVar1) {
          bVar4 = 0;
        }
        else {
          bVar4 = 1;
        }
      }
      else {
        bVar4 = 2;
      }
    }
    else {
      bVar4 = 3;
    }
  }
  else {
    bVar4 = 4;
  }
  FUN_800528f0();
  if (bVar4 < *(byte *)(iVar2 + 0x29)) {
    local_18 = 0xff;
    local_17 = 0xff;
    local_16 = 0xff;
    local_15 = *(undefined *)(param_1 + 0x36);
    uVar3 = FUN_800536c0(*(undefined4 *)(iVar2 + 0x24));
    FUN_80051d5c(uVar3,0,0,&local_18);
  }
  else {
    local_18 = 0;
    local_17 = 0;
    local_16 = 0;
    local_15 = (undefined)((*(byte *)(param_1 + 0x36) + 1) * 0x60 >> 8);
    uVar3 = FUN_800536c0(*(undefined4 *)(iVar2 + 0x24));
    FUN_80051d5c(uVar3,0,0,&local_18);
  }
  FUN_800528bc();
  if ((*(char *)(param_1 + 0x36) == -1) && (bVar4 < *(byte *)(iVar2 + 0x29))) {
    FUN_8025c584(0,1,0,5);
    FUN_80070310(1,3,1);
  }
  else {
    FUN_8025c584(1,4,5,5);
    FUN_80070310(1,3,0);
  }
  FUN_800702b8(1);
  FUN_8025bff0(7,0,0,7,0);
  FUN_80258b24(2);
  return 1;
}

