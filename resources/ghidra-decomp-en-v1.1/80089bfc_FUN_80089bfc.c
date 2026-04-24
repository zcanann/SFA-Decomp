// Function: FUN_80089bfc
// Entry: 80089bfc
// Size: 224 bytes

void FUN_80089bfc(int param_1)

{
  int iVar1;
  
  if (DAT_803dddc4 != (int *)0x0) {
    iVar1 = DAT_803dddac + param_1 * 0xa4;
    FUN_8001dd54((double)*(float *)(iVar1 + 0x90),(double)*(float *)(iVar1 + 0x94),
                 (double)*(float *)(iVar1 + 0x98),DAT_803dddc4);
    iVar1 = DAT_803dddac + param_1 * 0xa4;
    FUN_8001dbb4((int)DAT_803dddc4,*(undefined *)(iVar1 + 0x78),*(undefined *)(iVar1 + 0x79),
                 *(undefined *)(iVar1 + 0x7a),0xff);
  }
  if (DAT_803ddde8 != (int *)0x0) {
    iVar1 = DAT_803dddac + param_1 * 0xa4;
    FUN_8001dd54((double)*(float *)(iVar1 + 0x9c),(double)*(float *)(iVar1 + 0xa0),
                 (double)*(float *)(iVar1 + 0xa4),DAT_803ddde8);
    iVar1 = DAT_803dddac + param_1 * 0xa4;
    FUN_8001dbb4((int)DAT_803ddde8,*(undefined *)(iVar1 + 0x80),*(undefined *)(iVar1 + 0x81),
                 *(undefined *)(iVar1 + 0x82),0xff);
  }
  iVar1 = DAT_803dddac + param_1 * 0xa4;
  FUN_8001f0a4(0,*(undefined *)(iVar1 + 0x88),*(undefined *)(iVar1 + 0x89),
               *(undefined *)(iVar1 + 0x8a));
  return;
}

