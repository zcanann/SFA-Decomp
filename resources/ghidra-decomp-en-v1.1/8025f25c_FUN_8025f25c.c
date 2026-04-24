// Function: FUN_8025f25c
// Entry: 8025f25c
// Size: 284 bytes

int FUN_8025f25c(int param_1,int param_2)

{
  int iVar1;
  int iVar2;
  
  iVar2 = param_1 * 0x110;
  (&DAT_803afed4)[iVar2] = 0xf2;
  (&DAT_803afed5)[iVar2] = (byte)(*(uint *)(&DAT_803afef0 + iVar2) >> 0x11) & 0x7f;
  (&DAT_803afed6)[iVar2] = (char)(*(uint *)(&DAT_803afef0 + iVar2) >> 9);
  (&DAT_803afed7)[iVar2] = (byte)(*(uint *)(&DAT_803afef0 + iVar2) >> 7) & 3;
  (&DAT_803afed8)[iVar2] = (byte)*(undefined4 *)(&DAT_803afef0 + iVar2) & 0x7f;
  *(undefined4 *)(&DAT_803afee0 + iVar2) = 5;
  *(undefined4 *)(&DAT_803afee4 + iVar2) = 1;
  *(undefined4 *)(&DAT_803afee8 + iVar2) = 3;
  iVar1 = FUN_8025ef74(param_1,0,param_2);
  if (iVar1 == -1) {
    iVar1 = 0;
  }
  else if (-1 < iVar1) {
    iVar1 = FUN_80253c3c(param_1,&DAT_803afed4 + iVar2,*(int *)(&DAT_803afee0 + iVar2),1);
    if ((iVar1 == 0) ||
       (iVar1 = FUN_80253cdc(param_1,*(uint *)(&DAT_803afef4 + iVar2),0x80,
                             *(int *)(&DAT_803afee4 + iVar2),&LAB_8025e80c), iVar1 == 0)) {
      *(undefined4 *)(&DAT_803aff0c + iVar2) = 0;
      FUN_80254660(param_1);
      FUN_80254d28(param_1);
      iVar1 = -3;
    }
    else {
      iVar1 = 0;
    }
  }
  return iVar1;
}

