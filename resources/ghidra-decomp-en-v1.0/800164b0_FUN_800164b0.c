// Function: FUN_800164b0
// Entry: 800164b0
// Size: 220 bytes

void FUN_800164b0(undefined4 param_1,undefined4 param_2,int *param_3,int *param_4,int *param_5,
                 int *param_6)

{
  undefined2 uVar1;
  undefined2 uVar2;
  int iVar3;
  int extraout_r4;
  
  FUN_802860d4();
  iVar3 = extraout_r4 * 0x20;
  uVar1 = *(undefined2 *)(&DAT_802c7418 + iVar3);
  uVar2 = *(undefined2 *)(&DAT_802c741a + iVar3);
  DAT_803dc9bc = 1;
  DAT_803dc9b0 = 0x7fffffff;
  DAT_803dc9ac = 0;
  DAT_803dc9b8 = 0x7fffffff;
  DAT_803dc9b4 = 0;
  FUN_80015e84();
  DAT_803dc9bc = 0;
  if (param_5 != (int *)0x0) {
    *param_5 = DAT_803dc9b8 >> 2;
  }
  if (param_6 != (int *)0x0) {
    *param_6 = DAT_803dc9b4 >> 2;
  }
  if (param_3 != (int *)0x0) {
    *param_3 = DAT_803dc9b0 >> 2;
  }
  if (param_4 != (int *)0x0) {
    *param_4 = DAT_803dc9ac >> 2;
  }
  *(undefined2 *)(&DAT_802c7418 + iVar3) = uVar1;
  *(undefined2 *)(&DAT_802c741a + iVar3) = uVar2;
  FUN_80286120();
  return;
}

