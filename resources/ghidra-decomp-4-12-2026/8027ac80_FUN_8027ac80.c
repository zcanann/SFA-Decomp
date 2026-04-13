// Function: FUN_8027ac80
// Entry: 8027ac80
// Size: 240 bytes

void FUN_8027ac80(uint param_1,uint param_2)

{
  float fVar1;
  uint uVar2;
  uint uVar3;
  
  if (param_2 == 0xffffffff) {
    param_2 = 0x40005622;
  }
  uVar2 = param_2 >> 0x18;
  uVar3 = param_1 & 0xff;
  if (uVar3 == uVar2) {
    fVar1 = (float)((double)CONCAT44(0x43300000,param_2 & 0xffffff) - DOUBLE_803e84b8);
  }
  else {
    if (uVar2 < uVar3) {
      fVar1 = *(float *)(&DAT_8032fe78 + (uVar3 - uVar2) * 4);
    }
    else {
      fVar1 = *(float *)(&DAT_80330078 + (uVar2 - uVar3) * 4);
    }
    fVar1 = (float)((double)CONCAT44(0x43300000,param_2 & 0xffffff) - DOUBLE_803e84b8) * fVar1;
  }
  FUN_80286718((double)((FLOAT_803e84c0 * fVar1) /
                       (float)((double)CONCAT44(0x43300000,DAT_803bddb0) - DOUBLE_803e84b8)));
  return;
}

