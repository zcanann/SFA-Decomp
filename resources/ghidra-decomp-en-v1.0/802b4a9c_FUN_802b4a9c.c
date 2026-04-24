// Function: FUN_802b4a9c
// Entry: 802b4a9c
// Size: 380 bytes

void FUN_802b4a9c(undefined4 param_1,int param_2,int param_3)

{
  byte bVar1;
  int iVar2;
  undefined4 uVar3;
  float local_18 [3];
  
  iVar2 = (**(code **)(*DAT_803dca50 + 0x3c))();
  bVar1 = *(byte *)(param_2 + 0x3f4) >> 6 & 1;
  if (bVar1 != 0) {
    if ((*(uint *)(param_2 + 0x360) & 0x10) == 0) {
      if (iVar2 == 0) {
        *(undefined4 *)(param_3 + 0x2d0) = 0;
        *(undefined *)(param_3 + 0x349) = 0;
      }
      else {
        if ((*(int *)(param_3 + 0x2d0) != iVar2) &&
           (*(undefined *)(param_3 + 0x349) = 0, (*(byte *)(*(int *)(iVar2 + 0x78) + 4) & 0xf) == 1)
           ) {
          if ((DAT_803de44c != 0) && ((*(byte *)(param_2 + 0x3f4) >> 6 & 1) != 0)) {
            *(undefined *)(param_2 + 0x8b4) = 2;
            *(byte *)(param_2 + 0x3f4) = *(byte *)(param_2 + 0x3f4) & 0xf7;
          }
          *(undefined *)(param_3 + 0x349) = 1;
        }
        *(int *)(param_3 + 0x2d0) = iVar2;
      }
    }
    else {
      if ((DAT_803de44c != 0) && (bVar1 != 0)) {
        *(undefined *)(param_2 + 0x8b4) = 2;
        *(byte *)(param_2 + 0x3f4) = *(byte *)(param_2 + 0x3f4) & 0xf7;
      }
      *(undefined *)(param_3 + 0x349) = 1;
      if (iVar2 == 0) {
        local_18[0] = FLOAT_803e8150;
        uVar3 = FUN_80036e58(3,param_1,local_18);
        *(undefined4 *)(param_3 + 0x2d0) = uVar3;
      }
      else {
        *(int *)(param_3 + 0x2d0) = iVar2;
      }
    }
    if (*(int *)(param_3 + 0x2d0) == 0) {
      *(undefined2 *)(param_2 + 0x80e) = 0xffff;
    }
    else {
      FUN_8014c540(*(int *)(param_3 + 0x2d0),param_2 + 0x884,param_2 + 0x888,param_2 + 0x88c);
    }
  }
  return;
}

