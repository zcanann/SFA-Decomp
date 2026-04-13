// Function: FUN_8025f378
// Entry: 8025f378
// Size: 224 bytes

int FUN_8025f378(int param_1,uint param_2,int param_3)

{
  int iVar1;
  int iVar2;
  
  iVar2 = param_1 * 0x110;
  (&DAT_803afed4)[iVar2] = 0xf1;
  (&DAT_803afed5)[iVar2] = (byte)(param_2 >> 0x11) & 0x7f;
  (&DAT_803afed6)[iVar2] = (char)(param_2 >> 9);
  *(undefined4 *)(&DAT_803afee0 + iVar2) = 3;
  *(undefined4 *)(&DAT_803afee4 + iVar2) = 0xffffffff;
  *(undefined4 *)(&DAT_803afee8 + iVar2) = 3;
  iVar1 = FUN_8025ef74(param_1,0,param_3);
  if (iVar1 == -1) {
    iVar1 = 0;
  }
  else if (-1 < iVar1) {
    iVar1 = FUN_80253c3c(param_1,&DAT_803afed4 + iVar2,*(int *)(&DAT_803afee0 + iVar2),1);
    if (iVar1 == 0) {
      *(undefined4 *)(&DAT_803aff0c + iVar2) = 0;
      iVar1 = -3;
    }
    else {
      iVar1 = 0;
    }
    FUN_80254660(param_1);
    FUN_80254d28(param_1);
  }
  return iVar1;
}

